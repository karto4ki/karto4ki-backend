package userclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type PublicProfile struct {
	ID                string    `json:"id"`
	Username          string    `json:"username"`
	Name              string    `json:"name"`
	PhotoURL          *string   `json:"avatar_url,omitempty"`
	PublicSetsCount   int64     `json:"public_sets_count"`
	TotalViews        int64     `json:"total_views"`
	FollowersCount    int64     `json:"followers_count"`
	FollowingCount    int64     `json:"following_count"`
	JoinedAt          time.Time `json:"joined_at"`
}

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) GetPublicProfile(ctx context.Context, userID string) (*PublicProfile, error) {
	url := fmt.Sprintf("%s/v1.0/users/%s", c.baseURL, userID)
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Data *PublicProfile `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Data, nil
}

func (c *Client) GetPublicProfileByUsername(ctx context.Context, username string) (*PublicProfile, error) {
	url := fmt.Sprintf("%s/v1.0/user/%s", c.baseURL, username)
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Data *PublicProfile `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Data, nil
}
