package models

import "time"

type FileType string

const (
	FileTypeAvatar      FileType = "avatar"
	FileTypeCardImage   FileType = "card_image"
	FileTypeDocument    FileType = "document"
	FileTypeOther       FileType = "other"
)

type FileInfo struct {
	ID           string    `json:"id"`
	OwnerID      string    `json:"owner_id"`
	FileType     FileType  `json:"file_type"`
	FileSize     int64     `json:"file_size"`
	MimeType     string    `json:"mime_type"`
	URL          string    `json:"url"`
	ThumbnailURL *string   `json:"thumbnail_url,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type UploadResponse struct {
	FileID    string    `json:"file_id"`
	FileURL   string    `json:"file_url"`
	FileType  string    `json:"file_type"`
	FileSize  int64     `json:"file_size"`
	MimeType  string    `json:"mime_type"`
	CreatedAt time.Time `json:"created_at"`
}
