package grpc

import (
	"fmt"
	"net"

	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
	pb "github.com/karto4ki/karto4ki-backend/filestorage-service/proto"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

type Server struct {
	pb.UnimplementedFileStorageServiceServer
	uploadInitService     *services.UploadInitService
	uploadPartService     *services.UploadPartService
	uploadCompleteService *services.UploadCompleteService
	uploadAbortService    *services.UploadAbortService
}

func NewServer(
	uploadInitService *services.UploadInitService,
	uploadPartService *services.UploadPartService,
	uploadCompleteService *services.UploadCompleteService,
	uploadAbortService *services.UploadAbortService,
) *Server {
	return &Server{
		uploadInitService:     uploadInitService,
		uploadPartService:     uploadPartService,
		uploadCompleteService: uploadCompleteService,
		uploadAbortService:    uploadAbortService,
	}
}

func (s *Server) Register(server *grpc.Server) {
	pb.RegisterFileStorageServiceServer(server, s)
}

func (s *Server) Serve(lis net.Listener) error {
	grpcServer := grpc.NewServer()
	s.Register(grpcServer)
	return grpcServer.Serve(lis)
}

func StartServer(
	addr string,
	srv *Server,
	redisClient *redis.Client,
) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	return srv.Serve(lis)
}
