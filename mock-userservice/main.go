package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/karto4ki/karto4ki-backend/mock-userservice/userservice"
)

type mockUserServiceServer struct {
	pb.UnimplementedUserServiceServer
}

func (s *mockUserServiceServer) GetUserByEmail(ctx context.Context, req *pb.GetUserByEmailRequest) (*pb.GetUserResponse, error) {
	log.Printf("GetUserByEmail called with email: %s", req.Email)
	return &pb.GetUserResponse{
		Status: pb.GetUserResponseStatus_NOT_FOUND,
	}, nil
}

func (s *mockUserServiceServer) CreateUserWithEmail(ctx context.Context, req *pb.CreateUserWithEmailRequest) (*pb.CreateUserResponse, error) {
	log.Printf("CreateUserWithEmail called: %+v", req)
	return &pb.CreateUserResponse{
		Status:   pb.CreateUserStatus_CREATED,
		UserId:   &pb.UUID{Value: "123e4567-e89b-12d3-a456-426614174000"},
		Name:     &req.Name,
		Username: &req.Username,
	}, nil
}

func (s *mockUserServiceServer) GetUserByProvider(ctx context.Context, req *pb.GetUserByProviderRequest) (*pb.GetUserResponse, error) {
	return &pb.GetUserResponse{Status: pb.GetUserResponseStatus_NOT_FOUND}, nil
}

func (s *mockUserServiceServer) CreateUserWithProvider(ctx context.Context, req *pb.CreateUserWithProviderRequest) (*pb.CreateUserResponse, error) {
	return &pb.CreateUserResponse{Status: pb.CreateUserStatus_CREATED}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterUserServiceServer(s, &mockUserServiceServer{})
	log.Println("Mock User Service running on :50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
