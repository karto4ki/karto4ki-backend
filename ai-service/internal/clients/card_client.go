package clients

import (
	"context"
	"fmt"

	pb "github.com/karto4ki/karto4ki-backend/shared/proto/card"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type CardServiceClient struct {
	conn   *grpc.ClientConn
	client pb.CardServiceClient
}

func NewCardServiceClient(address string) (*CardServiceClient, error) {
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to card service: %w", err)
	}

	return &CardServiceClient{
		conn:   conn,
		client: pb.NewCardServiceClient(conn),
	}, nil
}

func (c *CardServiceClient) Close() error {
	return c.conn.Close()
}

type CreateCardSetResult struct {
	SetID string
}

func (c *CardServiceClient) CreateCardSet(ctx context.Context, ownerID, name string, description *string, isPublic bool) (*CreateCardSetResult, error) {
	desc := ""
	if description != nil {
		desc = *description
	}

	resp, err := c.client.CreateCardSet(ctx, &pb.CreateCardSetRequest{
		OwnerId:     ownerID,
		Name:        name,
		Description: desc,
		IsPublic:    isPublic,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create card set: %w", err)
	}

	return &CreateCardSetResult{
		SetID: resp.Set.Id,
	}, nil
}

type CreateCardResult struct {
	CardID string
}

func (c *CardServiceClient) CreateCard(ctx context.Context, setID, front, back string, imageURL, audioURL *string) (*CreateCardResult, error) {
	imgURL := ""
	if imageURL != nil {
		imgURL = *imageURL
	}
	audURL := ""
	if audioURL != nil {
		audURL = *audioURL
	}

	resp, err := c.client.CreateCard(ctx, &pb.CreateCardRequest{
		SetId:    setID,
		Front:    front,
		Back:     back,
		ImageUrl: imgURL,
		AudioUrl: audURL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create card: %w", err)
	}

	return &CreateCardResult{
		CardID: resp.Card.Id,
	}, nil
}

type DeleteCardSetResult struct{}

func (c *CardServiceClient) DeleteCardSet(ctx context.Context, setID, ownerID string) (*DeleteCardSetResult, error) {
	_, err := c.client.DeleteCardSet(ctx, &pb.DeleteCardSetRequest{
		SetId:   setID,
		OwnerId: ownerID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to delete card set: %w", err)
	}

	return &DeleteCardSetResult{}, nil
}
