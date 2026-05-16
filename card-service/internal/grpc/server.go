package grpc

import (
	"context"

	"github.com/karto4ki/karto4ki-backend/card-service/internal/services"
	pb "github.com/karto4ki/karto4ki-backend/shared/proto/card"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CardGRPCService struct {
	pb.UnimplementedCardServiceServer
	cardSetService *services.CardSetService
	cardService    *services.CardService
}

func NewCardGRPCService(cardSetService *services.CardSetService, cardService *services.CardService) *CardGRPCService {
	return &CardGRPCService{
		cardSetService: cardSetService,
		cardService:    cardService,
	}
}

func (s *CardGRPCService) CreateCardSet(ctx context.Context, req *pb.CreateCardSetRequest) (*pb.CreateCardSetResponse, error) {
	var description *string
	if req.Description != "" {
		description = &req.Description
	}

	set, err := s.cardSetService.CreateCardSet(ctx, req.OwnerId, req.Name, description, req.IsPublic)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create card set: %v", err)
	}

	desc := ""
	if set.Description != nil {
		desc = *set.Description
	}

	return &pb.CreateCardSetResponse{
		Set: &pb.CardSet{
			Id:          set.ID,
			OwnerId:     set.OwnerID,
			Name:        set.Name,
			Description: desc,
			IsPublic:    set.IsPublic,
			CardCount:   set.CardCount,
			CreatedAt:   timestamppb.New(set.CreatedAt),
		},
	}, nil
}

func (s *CardGRPCService) GetCardSet(ctx context.Context, req *pb.GetCardSetRequest) (*pb.GetCardSetResponse, error) {
	set, err := s.cardSetService.GetCardSet(ctx, req.SetId, req.OwnerId)
	if err != nil {
		if err == services.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, "card set not found")
		}
		if err == services.ErrForbidden {
			return nil, status.Errorf(codes.PermissionDenied, "access denied")
		}
		return nil, status.Errorf(codes.Internal, "failed to get card set: %v", err)
	}

	desc := ""
	if set.Description != nil {
		desc = *set.Description
	}

	return &pb.GetCardSetResponse{
		Set: &pb.CardSet{
			Id:          set.ID,
			OwnerId:     set.OwnerID,
			Name:        set.Name,
			Description: desc,
			IsPublic:    set.IsPublic,
			CardCount:   set.CardCount,
			CreatedAt:   timestamppb.New(set.CreatedAt),
		},
	}, nil
}

func (s *CardGRPCService) UpdateCardSet(ctx context.Context, req *pb.UpdateCardSetRequest) (*pb.UpdateCardSetResponse, error) {
	var description *string
	if req.Description != "" {
		description = &req.Description
	}

	set, err := s.cardSetService.UpdateCardSet(ctx, req.SetId, req.OwnerId, req.Name, description, req.IsPublic)
	if err != nil {
		if err == services.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, "card set not found")
		}
		if err == services.ErrForbidden {
			return nil, status.Errorf(codes.PermissionDenied, "access denied")
		}
		return nil, status.Errorf(codes.Internal, "failed to update card set: %v", err)
	}

	desc := ""
	if set.Description != nil {
		desc = *set.Description
	}

	return &pb.UpdateCardSetResponse{
		Set: &pb.CardSet{
			Id:          set.ID,
			OwnerId:     set.OwnerID,
			Name:        set.Name,
			Description: desc,
			IsPublic:    set.IsPublic,
			CardCount:   set.CardCount,
			CreatedAt:   timestamppb.New(set.CreatedAt),
		},
	}, nil
}

func (s *CardGRPCService) DeleteCardSet(ctx context.Context, req *pb.DeleteCardSetRequest) (*pb.DeleteCardSetResponse, error) {
	err := s.cardSetService.DeleteCardSet(ctx, req.SetId, req.OwnerId)
	if err != nil {
		if err == services.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, "card set not found")
		}
		if err == services.ErrForbidden {
			return nil, status.Errorf(codes.PermissionDenied, "access denied")
		}
		return nil, status.Errorf(codes.Internal, "failed to delete card set: %v", err)
	}

	return &pb.DeleteCardSetResponse{}, nil
}

func (s *CardGRPCService) CreateCard(ctx context.Context, req *pb.CreateCardRequest) (*pb.CreateCardResponse, error) {
	var imageURL, audioURL *string
	if req.ImageUrl != "" {
		imageURL = &req.ImageUrl
	}
	if req.AudioUrl != "" {
		audioURL = &req.AudioUrl
	}

	card, err := s.cardService.CreateCard(ctx, req.SetId, req.Front, req.Back, imageURL, audioURL)
	if err != nil {
		if err == services.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, "card set not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to create card: %v", err)
	}

	imgURL := ""
	if card.ImageURL != nil {
		imgURL = *card.ImageURL
	}
	audURL := ""
	if card.AudioURL != nil {
		audURL = *card.AudioURL
	}

	return &pb.CreateCardResponse{
		Card: &pb.Card{
			Id:        card.ID,
			SetId:     card.SetID,
			Front:     card.Front,
			Back:      card.Back,
			ImageUrl:  imgURL,
			AudioUrl:  audURL,
			CreatedAt: timestamppb.New(card.CreatedAt),
		},
	}, nil
}

func (s *CardGRPCService) GetCard(ctx context.Context, req *pb.GetCardRequest) (*pb.GetCardResponse, error) {
	card, err := s.cardService.GetCard(ctx, req.CardId, "")
	if err != nil {
		if err == services.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, "card not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get card: %v", err)
	}

	imgURL := ""
	if card.ImageURL != nil {
		imgURL = *card.ImageURL
	}
	audURL := ""
	if card.AudioURL != nil {
		audURL = *card.AudioURL
	}

	return &pb.GetCardResponse{
		Card: &pb.Card{
			Id:        card.ID,
			SetId:     card.SetID,
			Front:     card.Front,
			Back:      card.Back,
			ImageUrl:  imgURL,
			AudioUrl:  audURL,
			CreatedAt: timestamppb.New(card.CreatedAt),
		},
	}, nil
}

func (s *CardGRPCService) UpdateCard(ctx context.Context, req *pb.UpdateCardRequest) (*pb.UpdateCardResponse, error) {
	var imageURL, audioURL *string
	if req.ImageUrl != "" {
		imageURL = &req.ImageUrl
	}
	if req.AudioUrl != "" {
		audioURL = &req.AudioUrl
	}

	card, err := s.cardService.UpdateCard(ctx, req.CardId, "", req.Front, req.Back, imageURL, audioURL)
	if err != nil {
		if err == services.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, "card not found")
		}
		if err == services.ErrForbidden {
			return nil, status.Errorf(codes.PermissionDenied, "access denied")
		}
		return nil, status.Errorf(codes.Internal, "failed to update card: %v", err)
	}

	imgURL := ""
	if card.ImageURL != nil {
		imgURL = *card.ImageURL
	}
	audURL := ""
	if card.AudioURL != nil {
		audURL = *card.AudioURL
	}

	return &pb.UpdateCardResponse{
		Card: &pb.Card{
			Id:        card.ID,
			SetId:     card.SetID,
			Front:     card.Front,
			Back:      card.Back,
			ImageUrl:  imgURL,
			AudioUrl:  audURL,
			CreatedAt: timestamppb.New(card.CreatedAt),
		},
	}, nil
}

func (s *CardGRPCService) DeleteCard(ctx context.Context, req *pb.DeleteCardRequest) (*pb.DeleteCardResponse, error) {
	err := s.cardService.DeleteCard(ctx, req.CardId, "")
	if err != nil {
		if err == services.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, "card not found")
		}
		if err == services.ErrForbidden {
			return nil, status.Errorf(codes.PermissionDenied, "access denied")
		}
		return nil, status.Errorf(codes.Internal, "failed to delete card: %v", err)
	}

	return &pb.DeleteCardResponse{}, nil
}
