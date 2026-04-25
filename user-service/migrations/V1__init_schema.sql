CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    photo_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notification_enabled BOOLEAN DEFAULT TRUE,
    provider VARCHAR(50),
    provider_id VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS achievements (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    sets INT DEFAULT 0,
    streak INT DEFAULT 0
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_provider_id ON users(provider, provider_id);