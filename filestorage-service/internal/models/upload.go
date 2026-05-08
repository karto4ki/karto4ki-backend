package models

import (
	"time"

	"github.com/google/uuid"
)

// UploadMeta хранит метаданные многокомпонентной загрузки
type UploadMeta struct {
	PublicUploadID uuid.UUID `json:"public_upload_id"`
	FileID         uuid.UUID `json:"file_id"`
	Key            string    `json:"key"`             // S3 ключ (fileID)
	FileName       string    `json:"file_name"`       // оригинальное имя файла
	MimeType       string    `json:"mime_type"`       // MIME тип
	S3UploadID     string    `json:"s3_upload_id"`    // S3 multipart upload ID
	CreatedAt      time.Time `json:"created_at"`
}

// FileMeta хранит метаданные загруженного файла
type FileMeta struct {
	FileID    uuid.UUID `json:"file_id"`
	OwnerID   string    `json:"owner_id"`
	FileName  string    `json:"file_name"`
	MimeType  string    `json:"mime_type"`
	FileType  string    `json:"file_type"`
	FileSize  int64     `json:"file_size"`
	FileURL   string    `json:"file_url"`
	CreatedAt time.Time `json:"created_at"`
}

// UploadPart представляет часть многокомпонентной загрузки
type UploadPart struct {
	PartNumber int    `json:"part_number"`
	ETag       string `json:"e_tag"`
}
