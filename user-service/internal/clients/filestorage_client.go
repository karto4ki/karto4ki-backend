package clients

import (
	"context"
	"fmt"

	pb "github.com/karto4ki/karto4ki-backend/filestorage-service/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// FileStorageClient - клиент для взаимодействия с filestorage-service
type FileStorageClient struct {
	conn   *grpc.ClientConn
	client pb.FileStorageServiceClient
}

// NewFileStorageClient создает новый gRPC клиент
func NewFileStorageClient(addr string) (*FileStorageClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to filestorage service: %w", err)
	}

	return &FileStorageClient{
		conn:   conn,
		client: pb.NewFileStorageServiceClient(conn),
	}, nil
}

// Close закрывает соединение
func (c *FileStorageClient) Close() error {
	return c.conn.Close()
}

// UploadFile загружает файл через gRPC
func (c *FileStorageClient) UploadFile(ctx context.Context, data []byte, fileName, mimeType, fileType, ownerID string) (*pb.UploadFileResponse, error) {
	ft := pb.FileType_FILE_TYPE_OTHER
	switch fileType {
	case "avatar":
		ft = pb.FileType_FILE_TYPE_AVATAR
	case "card_image":
		ft = pb.FileType_FILE_TYPE_CARD_IMAGE
	case "document":
		ft = pb.FileType_FILE_TYPE_DOCUMENT
	}

	return c.client.UploadFile(ctx, &pb.UploadFileRequest{
		Data:     data,
		FileName: fileName,
		MimeType: mimeType,
		FileType: ft,
		OwnerId:  ownerID,
	})
}

// UploadInit инициализирует многокомпонентную загрузку
func (c *FileStorageClient) UploadInit(ctx context.Context, fileName, mimeType, fileType, ownerID string, totalSize int64) (*pb.UploadInitResponse, error) {
	ft := pb.FileType_FILE_TYPE_OTHER
	switch fileType {
	case "avatar":
		ft = pb.FileType_FILE_TYPE_AVATAR
	case "card_image":
		ft = pb.FileType_FILE_TYPE_CARD_IMAGE
	case "document":
		ft = pb.FileType_FILE_TYPE_DOCUMENT
	}

	return c.client.UploadInit(ctx, &pb.UploadInitRequest{
		FileName:  fileName,
		MimeType:  mimeType,
		FileType:  ft,
		OwnerId:   ownerID,
		TotalSize: totalSize,
	})
}

// UploadPart загружает часть файла
func (c *FileStorageClient) UploadPart(ctx context.Context, uploadID string, partNumber int32, data []byte) (*pb.UploadPartResponse, error) {
	return c.client.UploadPart(ctx, &pb.UploadPartRequest{
		UploadId:   uploadID,
		PartNumber: partNumber,
		Data:       data,
	})
}

// UploadComplete завершает многокомпонентную загрузку
func (c *FileStorageClient) UploadComplete(ctx context.Context, uploadID string, parts []*pb.UploadPartInfo) (*pb.UploadCompleteResponse, error) {
	return c.client.UploadComplete(ctx, &pb.UploadCompleteRequest{
		UploadId: uploadID,
		Parts:    parts,
	})
}

// UploadAbort отменяет загрузку
func (c *FileStorageClient) UploadAbort(ctx context.Context, uploadID string) error {
	_, err := c.client.UploadAbort(ctx, &pb.UploadAbortRequest{
		UploadId: uploadID,
	})
	return err
}
