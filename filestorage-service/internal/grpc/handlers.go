package grpc

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
	pb "github.com/karto4ki/karto4ki-backend/shared/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// UploadFile загружает файл целиком (для маленьких файлов)
func (s *Server) UploadFile(ctx context.Context, req *pb.UploadFileRequest) (*pb.UploadFileResponse, error) {
	// TODO: реализовать простую загрузку файла
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

// UploadInit инициализирует многокомпонентную загрузку
func (s *Server) UploadInit(ctx context.Context, req *pb.UploadInitRequest) (*pb.UploadInitResponse, error) {
	uploadID, err := s.uploadInitService.Init(ctx, &services.UploadInitRequest{
		FileName: req.FileName,
		MimeType: req.MimeType,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.UploadInitResponse{
		UploadId:    uploadID.String(),
		ChunkSize:   5 * 1024 * 1024, // 5MB
		TotalChunks: 1,
	}, nil
}

// UploadPart загружает часть файла
func (s *Server) UploadPart(ctx context.Context, req *pb.UploadPartRequest) (*pb.UploadPartResponse, error) {
	uploadID, err := uuid.Parse(req.UploadId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid upload_id")
	}

	resp, err := s.uploadPartService.UploadPart(ctx, &services.UploadPartRequest{
		PartNumber: int(req.PartNumber),
		UploadID:   uploadID,
		Part:       bytesReader(req.Data),
	})
	if err != nil {
		if errors.Is(err, services.ErrUploadNotFound) {
			return nil, status.Error(codes.NotFound, "upload not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.UploadPartResponse{
		ETag: resp.ETag,
	}, nil
}

// UploadComplete завершает многокомпонентную загрузку
func (s *Server) UploadComplete(ctx context.Context, req *pb.UploadCompleteRequest) (*pb.UploadCompleteResponse, error) {
	uploadID, err := uuid.Parse(req.UploadId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid upload_id")
	}

	parts := make([]services.UploadPart, 0, len(req.Parts))
	for _, p := range req.Parts {
		parts = append(parts, services.UploadPart{
			PartNumber: int(p.PartNumber),
			ETag:       p.ETag,
		})
	}

	file, err := s.uploadCompleteService.Complete(ctx, &services.UploadCompleteRequest{
		UploadID: uploadID,
		Parts:    parts,
	})
	if err != nil {
		if errors.Is(err, services.ErrUploadNotFound) {
			return nil, status.Error(codes.NotFound, "upload not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.UploadCompleteResponse{
		FileId:    file.FileID.String(),
		FileUrl:   file.FileURL,
		FileType:  modelToFileType(file.FileType),
		FileSize:  file.FileSize,
		MimeType:  file.MimeType,
		CreatedAt: timestamppb.New(file.CreatedAt),
	}, nil
}

// UploadAbort отменяет загрузку
func (s *Server) UploadAbort(ctx context.Context, req *pb.UploadAbortRequest) (*pb.UploadAbortResponse, error) {
	uploadID, err := uuid.Parse(req.UploadId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid upload_id")
	}

	err = s.uploadAbortService.Abort(ctx, uploadID)
	if err != nil {
		if errors.Is(err, services.ErrUploadNotFound) {
			return nil, status.Error(codes.NotFound, "upload not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.UploadAbortResponse{}, nil
}

// GetFile получает информацию о файле
func (s *Server) GetFile(ctx context.Context, req *pb.GetFileRequest) (*pb.GetFileResponse, error) {
	// TODO: реализовать получение информации о файле
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

// DeleteFile удаляет файл
func (s *Server) DeleteFile(ctx context.Context, req *pb.DeleteFileRequest) (*pb.DeleteFileResponse, error) {
	// TODO: реализовать удаление файла
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

// Вспомогательные функции

func bytesReader(data []byte) *byteReader {
	return &byteReader{data: data, pos: 0}
}

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("EOF")
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func pbFileTypeToModel(ft pb.FileType) string {
	switch ft {
	case pb.FileType_FILE_TYPE_AVATAR:
		return "avatar"
	case pb.FileType_FILE_TYPE_CARD_IMAGE:
		return "card_image"
	case pb.FileType_FILE_TYPE_DOCUMENT:
		return "document"
	default:
		return "other"
	}
}

func modelToFileType(ft string) pb.FileType {
	switch ft {
	case "avatar":
		return pb.FileType_FILE_TYPE_AVATAR
	case "card_image":
		return pb.FileType_FILE_TYPE_CARD_IMAGE
	case "document":
		return pb.FileType_FILE_TYPE_DOCUMENT
	default:
		return pb.FileType_FILE_TYPE_OTHER
	}
}
