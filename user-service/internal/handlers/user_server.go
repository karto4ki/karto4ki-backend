package handlers

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	pb "github.com/karto4ki/karto4ki-backend/user-service/internal/grpc"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/shared/validator"
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

	// Конвертируем провайдеры в protobuf
	providers := make([]*pb.OAuthProvider, len(user.Providers))
	for i, p := range user.Providers {
		providers[i] = &pb.OAuthProvider{
			Id:         p.ID.String(),
			UserId:     p.UserID.String(),
			Provider:   p.Provider,
			ProviderId: p.ProviderID,
			CreatedAt:  p.CreatedAt.Format(time.RFC3339),
		}
	}

	return &pb.GetUserResponse{
		Status:    pb.GetUserResponseStatus_SUCCESS,
		Name:      &user.Name,
		Username:  &user.Username,
		UserId:    &pb.UUID{Value: user.ID.String()},
		Providers: providers,
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

	// Конвертируем провайдеры в protobuf
	providers := make([]*pb.OAuthProvider, len(user.Providers))
	for i, p := range user.Providers {
		providers[i] = &pb.OAuthProvider{
			Id:         p.ID.String(),
			UserId:     p.UserID.String(),
			Provider:   p.Provider,
			ProviderId: p.ProviderID,
			CreatedAt:  p.CreatedAt.Format(time.RFC3339),
		}
	}

	return &pb.GetUserResponse{
		Status:    pb.GetUserResponseStatus_SUCCESS,
		Name:      &user.Name,
		Username:  &user.Username,
		UserId:    &pb.UUID{Value: user.ID.String()},
		Providers: providers,
	}, nil
}

func (s *GrpcServer) CreateUserWithEmail(ctx context.Context, req *pb.CreateUserWithEmailRequest) (*pb.CreateUserResponse, error) {
	if req.Email == "" || req.Name == "" || req.Username == "" {
		return &pb.CreateUserResponse{Status: pb.CreateUserStatus_VALIDATION_FAILED}, nil
	}

	if !validator.ValidateEmail(req.Email) {
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

func (s *GrpcServer) AddProviderToUser(ctx context.Context, req *pb.AddProviderToUserRequest) (*pb.AddProviderToUserResponse, error) {
	if req.UserId == nil || req.UserId.Value == "" || req.Provider == "" || req.ProviderId == "" {
		return &pb.AddProviderToUserResponse{Status: pb.AddProviderToUserStatus_ADD_PROVIDER_VALIDATION_FAILED}, nil
	}
	userID, err := uuid.Parse(req.UserId.Value)
	if err != nil {
		return &pb.AddProviderToUserResponse{Status: pb.AddProviderToUserStatus_ADD_PROVIDER_VALIDATION_FAILED}, nil
	}
	err = s.userSvc.AddProviderToUser(ctx, userID, req.Provider, req.ProviderId)
	if err != nil {
		if errors.Is(err, services.ErrAlreadyExists) {
			return &pb.AddProviderToUserResponse{Status: pb.AddProviderToUserStatus_ADD_PROVIDER_FAILED}, nil
		}
		return &pb.AddProviderToUserResponse{Status: pb.AddProviderToUserStatus_ADD_PROVIDER_FAILED}, nil
	}
	return &pb.AddProviderToUserResponse{Status: pb.AddProviderToUserStatus_ADD_PROVIDER_SUCCESS}, nil
}

func (s *GrpcServer) RemoveProviderFromUser(ctx context.Context, req *pb.RemoveProviderFromUserRequest) (*pb.RemoveProviderFromUserResponse, error) {
	if req.UserId == nil || req.UserId.Value == "" || req.Provider == "" {
		return &pb.RemoveProviderFromUserResponse{Status: pb.RemoveProviderFromUserStatus_REMOVE_PROVIDER_VALIDATION_FAILED}, nil
	}
	userID, err := uuid.Parse(req.UserId.Value)
	if err != nil {
		return &pb.RemoveProviderFromUserResponse{Status: pb.RemoveProviderFromUserStatus_REMOVE_PROVIDER_VALIDATION_FAILED}, nil
	}
	err = s.userSvc.RemoveProviderFromUser(ctx, userID, req.Provider)
	if err != nil {
		if errors.Is(err, services.ErrNotFound) {
			return &pb.RemoveProviderFromUserResponse{Status: pb.RemoveProviderFromUserStatus_REMOVE_PROVIDER_NOT_FOUND}, nil
		}
		return &pb.RemoveProviderFromUserResponse{Status: pb.RemoveProviderFromUserStatus_REMOVE_PROVIDER_FAILED}, nil
	}
	return &pb.RemoveProviderFromUserResponse{Status: pb.RemoveProviderFromUserStatus_REMOVE_PROVIDER_SUCCESS}, nil
}

func (s *GrpcServer) GetUserProviders(ctx context.Context, req *pb.GetUserProvidersRequest) (*pb.GetUserProvidersResponse, error) {
	if req.UserId == nil || req.UserId.Value == "" {
		return &pb.GetUserProvidersResponse{Status: pb.GetUserProvidersStatus_GET_PROVIDERS_VALIDATION_FAILED}, nil
	}
	userID, err := uuid.Parse(req.UserId.Value)
	if err != nil {
		return &pb.GetUserProvidersResponse{Status: pb.GetUserProvidersStatus_GET_PROVIDERS_FAILED}, nil
	}
	providers, err := s.userSvc.GetUserProviders(ctx, userID)
	if err != nil {
		return &pb.GetUserProvidersResponse{Status: pb.GetUserProvidersStatus_GET_PROVIDERS_FAILED}, nil
	}
	if len(providers) == 0 {
		return &pb.GetUserProvidersResponse{
			Status:     pb.GetUserProvidersStatus_GET_PROVIDERS_NOT_FOUND,
			Providers:  []*pb.OAuthProvider{},
		}, nil
	}

	// Конвертируем провайдеры в protobuf
	pbProviders := make([]*pb.OAuthProvider, len(providers))
	for i, p := range providers {
		pbProviders[i] = &pb.OAuthProvider{
			Id:         p.ID.String(),
			UserId:     p.UserID.String(),
			Provider:   p.Provider,
			ProviderId: p.ProviderID,
			CreatedAt:  p.CreatedAt.Format(time.RFC3339),
		}
	}

	return &pb.GetUserProvidersResponse{
		Status:    pb.GetUserProvidersStatus_GET_PROVIDERS_SUCCESS,
		Providers: pbProviders,
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

func (s *GrpcServer) SearchUsers(ctx context.Context, req *pb.SearchUsersRequest) (*pb.SearchUsersResponse, error) {
	if req.Query == "" {
		return &pb.SearchUsersResponse{
			Status: pb.GetUserResponseStatus_FAILED,
			Users:  []*pb.GetUserResponse{},
			Total:  0,
		}, nil
	}

	searchReq := storage.SearchUsersRequest{
		Query:  req.Query,
		Limit:  req.Limit,
		Offset: req.Offset,
	}

	result, err := s.userSvc.SearchUsers(ctx, searchReq)
	if err != nil {
		return &pb.SearchUsersResponse{
			Status: pb.GetUserResponseStatus_FAILED,
			Users:  []*pb.GetUserResponse{},
			Total:  0,
		}, nil
	}

	// Конвертируем пользователей в protobuf
	users := make([]*pb.GetUserResponse, len(result.Users))
	for i, user := range result.Users {
		name := user.Name
		username := user.Username
		photoURL := user.PhotoURL
		userID := &pb.UUID{Value: user.ID.String()}

		// Конвертируем провайдеры
		providers := make([]*pb.OAuthProvider, len(user.Providers))
		for j, p := range user.Providers {
			providers[j] = &pb.OAuthProvider{
				Id:         p.ID.String(),
				UserId:     p.UserID.String(),
				Provider:   p.Provider,
				ProviderId: p.ProviderID,
				CreatedAt:  p.CreatedAt.Format(time.RFC3339),
			}
		}

		users[i] = &pb.GetUserResponse{
			Status:    pb.GetUserResponseStatus_SUCCESS,
			Name:      &name,
			Username:  &username,
			UserId:    userID,
			PhotoUrl:  photoURL,
			Providers: providers,
		}
	}

	return &pb.SearchUsersResponse{
		Status: pb.GetUserResponseStatus_SUCCESS,
		Users:  users,
		Total:  result.Total,
	}, nil
}

func (s *GrpcServer) CopyCardSet(ctx context.Context, req *pb.CopyCardSetRequest) (*pb.CopyCardSetResponse, error) {
	if req.UserId == nil || req.SetId == nil {
		return &pb.CopyCardSetResponse{
			Status: pb.CopyCardSetStatus_COPY_SET_VALIDATION_FAILED,
		}, nil
	}

	userID, err := uuid.Parse(req.UserId.Value)
	if err != nil {
		return &pb.CopyCardSetResponse{
			Status: pb.CopyCardSetStatus_COPY_SET_VALIDATION_FAILED,
		}, nil
	}

	setID, err := uuid.Parse(req.SetId.Value)
	if err != nil {
		return &pb.CopyCardSetResponse{
			Status: pb.CopyCardSetStatus_COPY_SET_VALIDATION_FAILED,
		}, nil
	}

	newSetID := uuid.New()
	copyReq := storage.CopyCardSetRequest{
		UserID:   userID,
		SetID:    setID,
		NewSetID: newSetID,
	}

	err = s.userSvc.CopyCardSet(ctx, copyReq)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return &pb.CopyCardSetResponse{
				Status: pb.CopyCardSetStatus_COPY_SET_NOT_FOUND,
			}, nil
		}
		return &pb.CopyCardSetResponse{
			Status: pb.CopyCardSetStatus_COPY_SET_FAILED,
		}, nil
	}

	return &pb.CopyCardSetResponse{
		Status:   pb.CopyCardSetStatus_COPY_SET_SUCCESS,
		NewSetId: &pb.UUID{Value: newSetID.String()},
	}, nil
}
