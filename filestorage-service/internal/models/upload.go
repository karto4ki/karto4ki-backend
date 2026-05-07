package models

import "time"

// UploadSession представляет сессию загрузки файла частями
type UploadSession struct {
	UploadID    string    `json:"upload_id"`
	Filename    string    `json:"filename"`
	FileType    FileType  `json:"file_type"`
	OwnerID     string    `json:"owner_id"`
	TotalSize   int64     `json:"total_size"`
	ChunkSize   int64     `json:"chunk_size"`
	TotalChunks int       `json:"total_chunks"`
	UploadedAt  time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ChunkInfo представляет информацию о части файла
type ChunkInfo struct {
	ChunkNumber int    `json:"chunk_number"`
	ChunkSize   int64  `json:"chunk_size"`
	ETag        string `json:"etag,omitempty"`
}

// UploadInitRequest запрос на инициализацию загрузки
type UploadInitRequest struct {
	Filename  string   `json:"filename"`
	FileType  FileType `json:"file_type"`
	TotalSize int64    `json:"total_size"`
	ChunkSize int64    `json:"chunk_size,omitempty"` // опционально, по умолчанию 5MB
}

// UploadInitResponse ответ на инициализацию загрузки
type UploadInitResponse struct {
	UploadID    string `json:"upload_id"`
	ChunkSize   int64  `json:"chunk_size"`
	TotalChunks int    `json:"total_chunks"`
	ExpiresIn   int64  `json:"expires_in"` // секунд до истечения сессии
}

// UploadChunkRequest запрос на загрузку части файла
type UploadChunkRequest struct {
	UploadID    string `form:"upload_id"`
	ChunkNumber int    `form:"chunk_number"`
	TotalChunks int    `form:"total_chunks"`
}

// UploadChunkResponse ответ на загрузку части файла
type UploadChunkResponse struct {
	UploadID    string `json:"upload_id"`
	ChunkNumber int    `json:"chunk_number"`
	ETag        string `json:"etag"`
	Uploaded    int    `json:"uploaded_chunks"`
	TotalChunks int    `json:"total_chunks"`
}

// UploadCompleteRequest запрос на завершение загрузки
type UploadCompleteRequest struct {
	UploadID string `json:"upload_id"`
}

// UploadCompleteResponse ответ на завершение загрузки
type UploadCompleteResponse struct {
	FileID    string `json:"file_id"`
	FileURL   string `json:"file_url"`
	FileType  string `json:"file_type"`
	FileSize  int64  `json:"file_size"`
	MimeType  string `json:"mime_type"`
	CreatedAt time.Time `json:"created_at"`
}

// UploadAbortRequest запрос на отмену загрузки
type UploadAbortRequest struct {
	UploadID string `json:"upload_id"`
}
