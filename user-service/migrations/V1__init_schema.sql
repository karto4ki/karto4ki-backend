-- Karto4ki User Service Database Schema
-- Supports multiple OAuth providers per user

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    photo_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notification_enabled BOOLEAN DEFAULT TRUE
);

-- OAuth providers table (one user can have multiple providers)
CREATE TABLE IF NOT EXISTS user_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,  -- 'apple', 'google', 'yandex', etc.
    provider_id VARCHAR(255) NOT NULL,  -- ID from provider
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT unique_provider UNIQUE(provider, provider_id)
);

-- Achievements table
CREATE TABLE IF NOT EXISTS achievements (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    sets INT DEFAULT 0,
    streak INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_user_providers_user_id ON user_providers(user_id);
CREATE INDEX IF NOT EXISTS idx_user_providers_provider ON user_providers(provider, provider_id);

-- Comments
COMMENT ON TABLE users IS 'Пользователи приложения';
COMMENT ON TABLE user_providers IS 'Связь пользователей с OAuth провайдерами (один пользователь - много провайдеров)';
COMMENT ON TABLE achievements IS 'Достижения пользователей';

COMMENT ON COLUMN users.email IS 'Email пользователя (может быть NULL для OAuth без email)';
COMMENT ON COLUMN users.username IS 'Уникальное имя пользователя';
COMMENT ON COLUMN user_providers.provider IS 'Название провайдера: apple, google, yandex, etc.';
COMMENT ON COLUMN user_providers.provider_id IS 'Уникальный ID пользователя у провайдера';
