package services

import "errors"

var (
	ErrUserServiceUnavailable      = errors.New("user service unavailable")
	ErrUserCreationFailed          = errors.New("failed to create user")
	ErrUnexpectedUserServiceStatus = errors.New("unexpected user service status")
	ErrProviderAlreadyLinked       = errors.New("provider already linked to another user")
)
