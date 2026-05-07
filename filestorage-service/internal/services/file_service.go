package services

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"image"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/disintegration/imaging"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/models"
	"github.com/minio/minio-go/v7"
)

type Config struct {
	StoragePath    string
	MaxFileSize    int64
	AllowedTypes   []string
	ThumbnailSizes map[string]int
	S3Client       *minio.Client
	S3Bucket       string
	S3Enabled      bool
	ChunkSize      int64 // размер части для chunked upload (по умолчанию 5MB)
}

type FileService struct {
	config         Config
	uploadSessions sync.Map // map[uploadID]*models.UploadSession
	chunkStore     sync.Map // map[uploadID]map[chunkNum][]byte
}

func NewFileService(config Config) *FileService {
	return &FileService{config: config}
}

func (s *FileService) Upload(ctx context.Context, file io.Reader, filename string, fileType models.FileType, ownerID string) (*models.UploadResponse, error) {
	if err := s.validateFileType(filename); err != nil {
		return nil, err
	}

	fileID := uuid.New().String()
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		ext = ".jpg"
	}

	objectName := fmt.Sprintf("%s/%s%s", fileType, fileID, ext)

	var fileSize int64
	var err error

	if s.config.S3Enabled && s.config.S3Client != nil {
		fileSize, err = s.uploadToS3(ctx, file, objectName)
	} else {
		fileSize, err = s.uploadLocal(file, objectName)
	}

	if err != nil {
		return nil, err
	}

	fileURL := fmt.Sprintf("/api/storage/v1.0/files/%s/raw", fileID)

	return &models.UploadResponse{
		FileID:    fileID,
		FileURL:   fileURL,
		FileType:  string(fileType),
		FileSize:  fileSize,
		MimeType:  s.getMimeType(ext),
		CreatedAt: time.Now(),
	}, nil
}

func (s *FileService) uploadToS3(ctx context.Context, reader io.Reader, objectName string) (int64, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return 0, fmt.Errorf("failed to read file: %w", err)
	}

	_, err = s.config.S3Client.PutObject(ctx, s.config.S3Bucket, objectName, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
		ContentType: s.getMimeType(filepath.Ext(objectName)),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to upload to S3: %w", err)
	}

	return int64(len(data)), nil
}

func (s *FileService) uploadLocal(reader io.Reader, objectName string) (int64, error) {
	storageDir := filepath.Join(s.config.StoragePath, filepath.Dir(objectName))
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create storage directory: %w", err)
	}

	filePath := filepath.Join(s.config.StoragePath, objectName)
	dstFile, err := os.Create(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to create file: %w", err)
	}
	defer dstFile.Close()

	written, err := io.Copy(dstFile, reader)
	if err != nil {
		os.Remove(filePath)
		return 0, fmt.Errorf("failed to write file: %w", err)
	}

	if written > s.config.MaxFileSize {
		os.Remove(filePath)
		return 0, fmt.Errorf("file size exceeds limit")
	}

	return written, nil
}

func (s *FileService) GetFile(ctx context.Context, fileID string) (*models.FileInfo, error) {
	var objectName string
	var fileSize int64
	var mimeType string
	var createdAt time.Time

	if s.config.S3Enabled && s.config.S3Client != nil {
		objInfo, err := s.config.S3Client.StatObject(ctx, s.config.S3Bucket, fmt.Sprintf("%s/*", fileID), minio.StatObjectOptions{})
		if err != nil {
			return nil, fmt.Errorf("file not found")
		}
		objectName = objInfo.Key
		fileSize = objInfo.Size
		mimeType = objInfo.ContentType
		createdAt = objInfo.LastModified
	} else {
		filePath, fileInfo, err := s.findFile(fileID)
		if err != nil {
			return nil, err
		}
		objectName = filePath
		fileSize = fileInfo.Size()
		mimeType = s.getMimeType(filepath.Ext(filePath))
		createdAt = fileInfo.ModTime()
	}

	fileType := s.getFileType(objectName)
	var thumbnailURL *string
	if s.isImage(filepath.Ext(objectName)) {
		thumbURL := fmt.Sprintf("/api/storage/v1.0/images/%s/thumbnail?size=small", fileID)
		thumbnailURL = &thumbURL
	}

	return &models.FileInfo{
		ID:           fileID,
		OwnerID:      "",
		FileType:     fileType,
		FileSize:     fileSize,
		MimeType:     mimeType,
		URL:          fmt.Sprintf("/api/storage/v1.0/files/%s/raw", fileID),
		ThumbnailURL: thumbnailURL,
		CreatedAt:    createdAt,
	}, nil
}

func (s *FileService) DeleteFile(ctx context.Context, fileID string) error {
	if s.config.S3Enabled && s.config.S3Client != nil {
		// Для S3 нужно найти объект по fileID
		// Упрощенно - пытаемся удалить все возможные расширения
		for _, fileType := range []models.FileType{models.FileTypeAvatar, models.FileTypeCardImage, models.FileTypeDocument, models.FileTypeOther} {
			for _, ext := range []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".pdf", ".doc", ".docx"} {
				objectName := fmt.Sprintf("%s/%s%s", fileType, fileID, ext)
				err := s.config.S3Client.RemoveObject(ctx, s.config.S3Bucket, objectName, minio.RemoveObjectOptions{})
				if err == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("file not found")
	}

	filePath, _, err := s.findFile(fileID)
	if err != nil {
		return err
	}

	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

func (s *FileService) GetRawFile(ctx context.Context, fileID string) (string, []byte, error) {
	if s.config.S3Enabled && s.config.S3Client != nil {
		for _, fileType := range []models.FileType{models.FileTypeAvatar, models.FileTypeCardImage, models.FileTypeDocument, models.FileTypeOther} {
			for _, ext := range []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".pdf", ".doc", ".docx"} {
				objectName := fmt.Sprintf("%s/%s%s", fileType, fileID, ext)
				obj, err := s.config.S3Client.GetObject(ctx, s.config.S3Bucket, objectName, minio.GetObjectOptions{})
				if err != nil {
					continue
				}
				defer obj.Close()

				data, err := io.ReadAll(obj)
				if err != nil {
					return "", nil, fmt.Errorf("failed to read file: %w", err)
				}

				return s.getMimeType(ext), data, nil
			}
		}
		return "", nil, fmt.Errorf("file not found")
	}

	filePath, _, err := s.findFile(fileID)
	if err != nil {
		return "", nil, err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read file: %w", err)
	}

	return s.getMimeType(filepath.Ext(filePath)), data, nil
}

func (s *FileService) ResizeImage(ctx context.Context, imageID string, width, height int, fit string) (string, []byte, error) {
	var img image.Image
	var err error

	if s.config.S3Enabled && s.config.S3Client != nil {
		img, err = s.loadImageFromS3(ctx, imageID)
	} else {
		img, err = s.loadImageLocal(imageID)
	}

	if err != nil {
		return "", nil, err
	}

	var resized image.Image
	switch fit {
	case "contain":
		resized = imaging.Fit(img, width, height, imaging.Lanczos)
	case "fill":
		resized = imaging.Fill(img, width, height, imaging.Center, imaging.Lanczos)
	default:
		resized = imaging.Fill(img, width, height, imaging.Center, imaging.Lanczos)
	}

	var bufData []byte
	buf := &buffer{data: &bufData}
	if err := imaging.Encode(buf, resized, imaging.JPEG, imaging.JPEGQuality(90)); err != nil {
		return "", nil, fmt.Errorf("failed to encode image: %w", err)
	}

	return "image/jpeg", bufData, nil
}

func (s *FileService) loadImageFromS3(ctx context.Context, imageID string) (image.Image, error) {
	for _, ext := range []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"} {
		for _, fileType := range []models.FileType{models.FileTypeAvatar, models.FileTypeCardImage, models.FileTypeOther} {
			objectName := fmt.Sprintf("%s/%s%s", fileType, imageID, ext)
			obj, err := s.config.S3Client.GetObject(ctx, s.config.S3Bucket, objectName, minio.GetObjectOptions{})
			if err != nil {
				continue
			}
			defer obj.Close()

			img, err := imaging.Decode(obj)
			if err == nil {
				return img, nil
			}
		}
	}
	return nil, fmt.Errorf("image not found")
}

func (s *FileService) loadImageLocal(imageID string) (image.Image, error) {
	filePath, _, err := s.findFile(imageID)
	if err != nil {
		return nil, err
	}

	img, err := imaging.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open image: %w", err)
	}

	return img, nil
}

func (s *FileService) GetThumbnail(ctx context.Context, imageID string, size string) (string, []byte, error) {
	sizePixels, ok := s.config.ThumbnailSizes[size]
	if !ok {
		sizePixels = 100
	}

	return s.ResizeImage(ctx, imageID, sizePixels, sizePixels, "cover")
}

func (s *FileService) validateFileType(filename string) error {
	ext := strings.ToLower(filepath.Ext(filename))
	mimeType := s.getMimeType(ext)

	for _, allowed := range s.config.AllowedTypes {
		if allowed == mimeType || allowed == "*/*" {
			return nil
		}
	}

	return fmt.Errorf("file type not allowed")
}

func (s *FileService) findFile(fileID string) (string, os.FileInfo, error) {
	for _, fileType := range []models.FileType{models.FileTypeAvatar, models.FileTypeCardImage, models.FileTypeDocument, models.FileTypeOther} {
		storageDir := filepath.Join(s.config.StoragePath, string(fileType))
		
		for _, ext := range []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".pdf", ".doc", ".docx"} {
			filePath := filepath.Join(storageDir, fileID+ext)
			fileInfo, err := os.Stat(filePath)
			if err == nil {
				return filePath, fileInfo, nil
			}
		}
	}

	return "", nil, fmt.Errorf("file not found")
}

func (s *FileService) getFileType(filePath string) models.FileType {
	if strings.Contains(filePath, "/avatar/") {
		return models.FileTypeAvatar
	}
	if strings.Contains(filePath, "/card_image/") {
		return models.FileTypeCardImage
	}
	if strings.Contains(filePath, "/document/") {
		return models.FileTypeDocument
	}
	return models.FileTypeOther
}

func (s *FileService) isImage(ext string) bool {
	images := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true,
		".gif": true, ".webp": true, ".svg": true,
	}
	return images[ext]
}

func (s *FileService) getMimeType(ext string) string {
	mimes := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".svg":  "image/svg+xml",
		".pdf":  "application/pdf",
		".doc":  "application/msword",
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	}
	if mime, ok := mimes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}

// ========== Chunked Upload Methods ==========

// InitUpload инициализирует сессию загрузки файла частями
func (s *FileService) InitUpload(ctx context.Context, req *models.UploadInitRequest, ownerID string) (*models.UploadInitResponse, error) {
	if err := s.validateFileType(req.Filename); err != nil {
		return nil, err
	}

	chunkSize := req.ChunkSize
	if chunkSize <= 0 {
		chunkSize = s.config.ChunkSize
		if chunkSize <= 0 {
			chunkSize = 5 * 1024 * 1024 // 5MB по умолчанию
		}
	}

	totalChunks := int((req.TotalSize + chunkSize - 1) / chunkSize)
	uploadID := uuid.New().String()
	now := time.Now()

	session := &models.UploadSession{
		UploadID:    uploadID,
		Filename:    req.Filename,
		FileType:    req.FileType,
		OwnerID:     ownerID,
		TotalSize:   req.TotalSize,
		ChunkSize:   chunkSize,
		TotalChunks: totalChunks,
		UploadedAt:  now,
		ExpiresAt:   now.Add(24 * time.Hour), // сессия действительна 24 часа
	}

	s.uploadSessions.Store(uploadID, session)
	s.chunkStore.Store(uploadID, make(map[int][]byte))

	return &models.UploadInitResponse{
		UploadID:    uploadID,
		ChunkSize:   chunkSize,
		TotalChunks: totalChunks,
		ExpiresIn:   86400, // 24 часа в секундах
	}, nil
}

// UploadChunk загружает часть файла
func (s *FileService) UploadChunk(ctx context.Context, uploadID string, chunkNumber int, chunkData []byte) (*models.UploadChunkResponse, error) {
	sessionVal, ok := s.uploadSessions.Load(uploadID)
	if !ok {
		return nil, fmt.Errorf("upload session not found")
	}
	session := sessionVal.(*models.UploadSession)

	// Проверка срока действия сессии
	if time.Now().After(session.ExpiresAt) {
		s.cleanupUpload(uploadID)
		return nil, fmt.Errorf("upload session expired")
	}

	// Проверка номера части
	if chunkNumber < 1 || chunkNumber > session.TotalChunks {
		return nil, fmt.Errorf("invalid chunk number")
	}

	// Вычисляем ETag для части
	etag := fmt.Sprintf("%x", md5.Sum(chunkData))

	// Сохраняем часть в памяти
	chunksVal, ok := s.chunkStore.Load(uploadID)
	if !ok {
		return nil, fmt.Errorf("failed to get chunk store")
	}
	chunks := chunksVal.(map[int][]byte)
	
	chunksMu := &sync.Mutex{}
	chunksMu.Lock()
	chunks[chunkNumber] = chunkData
	chunksMu.Unlock()

	uploadedCount := len(chunks)

	return &models.UploadChunkResponse{
		UploadID:    uploadID,
		ChunkNumber: chunkNumber,
		ETag:        etag,
		Uploaded:    uploadedCount,
		TotalChunks: session.TotalChunks,
	}, nil
}

// CompleteUpload завершает загрузку и собирает файл из частей
func (s *FileService) CompleteUpload(ctx context.Context, uploadID string) (*models.UploadCompleteResponse, error) {
	sessionVal, ok := s.uploadSessions.Load(uploadID)
	if !ok {
		return nil, fmt.Errorf("upload session not found")
	}
	session := sessionVal.(*models.UploadSession)

	// Проверка срока действия сессии
	if time.Now().After(session.ExpiresAt) {
		s.cleanupUpload(uploadID)
		return nil, fmt.Errorf("upload session expired")
	}

	// Получаем все части
	chunksVal, ok := s.chunkStore.Load(uploadID)
	if !ok {
		return nil, fmt.Errorf("failed to get chunks")
	}
	chunks := chunksVal.(map[int][]byte)

	// Проверяем, что все части загружены
	if len(chunks) != session.TotalChunks {
		return nil, fmt.Errorf("not all chunks uploaded: got %d, expected %d", len(chunks), session.TotalChunks)
	}

	// Собираем части в правильном порядке
	var sortedKeys []int
	for k := range chunks {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Ints(sortedKeys)

	// Создаем объединенный reader
	readers := make([]io.Reader, 0, len(chunks))
	for _, k := range sortedKeys {
		readers = append(readers, bytes.NewReader(chunks[k]))
	}
	combinedReader := io.MultiReader(readers...)

	// Загружаем файл через стандартный метод
	fileID := uuid.New().String()
	ext := strings.ToLower(filepath.Ext(session.Filename))
	if ext == "" {
		ext = ".bin"
	}
	objectName := fmt.Sprintf("%s/%s%s", session.FileType, fileID, ext)

	var fileSize int64
	var err error

	if s.config.S3Enabled && s.config.S3Client != nil {
		fileSize, err = s.uploadToS3(ctx, combinedReader, objectName)
	} else {
		fileSize, err = s.uploadLocal(combinedReader, objectName)
	}

	if err != nil {
		return nil, err
	}

	// Очищаем сессию
	s.cleanupUpload(uploadID)

	fileURL := fmt.Sprintf("/api/storage/v1.0/files/%s/raw", fileID)

	return &models.UploadCompleteResponse{
		FileID:    fileID,
		FileURL:   fileURL,
		FileType:  string(session.FileType),
		FileSize:  fileSize,
		MimeType:  s.getMimeType(ext),
		CreatedAt: time.Now(),
	}, nil
}

// AbortUpload отменяет загрузку и очищает ресурсы
func (s *FileService) AbortUpload(ctx context.Context, uploadID string) error {
	s.cleanupUpload(uploadID)
	return nil
}

// cleanupUpload очищает сессию и части
func (s *FileService) cleanupUpload(uploadID string) {
	s.uploadSessions.Delete(uploadID)
	s.chunkStore.Delete(uploadID)
}

type buffer struct {
	data *[]byte
}

func (b *buffer) Write(p []byte) (n int, err error) {
	*b.data = append(*b.data, p...)
	return len(p), nil
}
