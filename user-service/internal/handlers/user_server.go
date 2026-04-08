package handlers

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"
	pb "github.com/karto4ki/karto4ki-backend/user-service/internal/grpc"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
)

type GrpcServer struct {
	pb.UnimplementedUserServiceServer
	pb.UnimplementedCardServiceServer
	userSvc        *services.UserService
	achievementSvc *services.AchievementService
}

func NewGrpcServer(userSvc *services.UserService, achievementSvc *services.AchievementService) *GrpcServer {
	return &GrpcServer{
		userSvc:        userSvc,
		achievementSvc: achievementSvc,
	}
}

func (s *GrpcServer) GetUserByEmail(ctx context.Context, req *pb.GetUserByEmailRequest) (*pb.GetUserResponse, error) {
	user, err := s.userSvc.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, services.ErrNotFound) {
			log.Printf("User not found by email: %s", req.Email)
			return &pb.GetUserResponse{
				Status: pb.GetUserResponseStatus_NOT_FOUND,
			}, nil
		}
		log.Printf("Error getting user by email: %v", err)
		return &pb.GetUserResponse{
			Status: pb.GetUserResponseStatus_FAILED,
		}, nil
	}
	return &pb.GetUserResponse{
		Status:   pb.GetUserResponseStatus_SUCCESS,
		Name:     &user.Name,
		Username: &user.Username,
		UserId:   &pb.UUID{Value: user.ID.String()},
	}, nil
}

func (s *GrpcServer) GetUserByProvider(ctx context.Context, req *pb.GetUserByProviderRequest) (*pb.GetUserResponse, error) {
	if req.ProviderId == nil {
		return &pb.GetUserResponse{Status: pb.GetUserResponseStatus_FAILED}, nil
	}
	user, err := s.userSvc.GetUserByProvider(ctx, req.Provider, req.ProviderId.Value)
	if err != nil {
		if errors.Is(err, services.ErrNotFound) {
			return &pb.GetUserResponse{Status: pb.GetUserResponseStatus_NOT_FOUND}, nil
		}
		return &pb.GetUserResponse{Status: pb.GetUserResponseStatus_FAILED}, nil
	}
	return &pb.GetUserResponse{
		Status:   pb.GetUserResponseStatus_SUCCESS,
		Name:     &user.Name,
		Username: &user.Username,
		UserId:   &pb.UUID{Value: user.ID.String()},
	}, nil
}

func (s *GrpcServer) CreateUserWithEmail(ctx context.Context, req *pb.CreateUserWithEmailRequest) (*pb.CreateUserResponse, error) {
	if req.Email == "" || req.Name == "" || req.Username == "" {
		return &pb.CreateUserResponse{Status: pb.CreateUserStatus_VALIDATION_FAILED}, nil
	}
	user, err := s.userSvc.CreateUserWithEmail(ctx, req.Email, req.Name, req.Username)
	if err != nil {
		if errors.Is(err, services.ErrAlreadyExists) {
			return &pb.CreateUserResponse{Status: pb.CreateUserStatus_ALREADY_EXISTS}, nil
		}
		log.Printf("CreateUserWithEmail failed: %v", err)
		return &pb.CreateUserResponse{Status: pb.CreateUserStatus_CREATE_FAILED}, nil
	}
	if err := s.achievementSvc.Create(ctx, user.ID); err != nil {
		log.Printf("Failed to create achievements for user %s: %v", user.ID, err)
	}
	return &pb.CreateUserResponse{
		Status:   pb.CreateUserStatus_CREATED,
		UserId:   &pb.UUID{Value: user.ID.String()},
		Name:     &user.Name,
		Username: &user.Username,
	}, nil
}

func (s *GrpcServer) CreateUserWithProvider(ctx context.Context, req *pb.CreateUserWithProviderRequest) (*pb.CreateUserResponse, error) {
	if req.Provider == "" || req.ProviderId == "" || req.Name == "" || req.Username == "" {
		return &pb.CreateUserResponse{Status: pb.CreateUserStatus_VALIDATION_FAILED}, nil
	}
	user, err := s.userSvc.CreateUserWithProvider(ctx, req.Provider, req.ProviderId, req.Name, req.Username)
	if err != nil {
		if errors.Is(err, services.ErrAlreadyExists) {
			return &pb.CreateUserResponse{Status: pb.CreateUserStatus_ALREADY_EXISTS}, nil
		}
		return &pb.CreateUserResponse{Status: pb.CreateUserStatus_CREATE_FAILED}, nil
	}
	if err := s.achievementSvc.Create(ctx, user.ID); err != nil {
		log.Printf("Failed to create achievements for user %s: %v", user.ID, err)
	}
	return &pb.CreateUserResponse{
		Status:   pb.CreateUserStatus_CREATED,
		UserId:   &pb.UUID{Value: user.ID.String()},
		Name:     &user.Name,
		Username: &user.Username,
	}, nil
}

func (s *GrpcServer) UpdateUserAchievements(ctx context.Context, req *pb.UpdateUserAchievementsRequest) (*pb.UpdateUserAchievementsResponse, error) {
	if req.UserId == nil || req.UserId.Value == "" {
		return &pb.UpdateUserAchievementsResponse{Status: pb.GetUserResponseStatus_FAILED}, nil
	}
	userID, err := uuid.Parse(req.UserId.Value)
	if err != nil {
		return &pb.UpdateUserAchievementsResponse{Status: pb.GetUserResponseStatus_FAILED}, nil
	}
	err = s.achievementSvc.UpdateSets(ctx, userID, req.Sets)
	if err != nil {
		if errors.Is(err, services.ErrNotFound) {
			return &pb.UpdateUserAchievementsResponse{Status: pb.GetUserResponseStatus_NOT_FOUND}, nil
		}
		return &pb.UpdateUserAchievementsResponse{Status: pb.GetUserResponseStatus_FAILED}, nil
	}
	return &pb.UpdateUserAchievementsResponse{Status: pb.GetUserResponseStatus_SUCCESS}, nil
}
