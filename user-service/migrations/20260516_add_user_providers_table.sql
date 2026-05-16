CREATE TABLE IF NOT EXISTS user_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,  -- 'apple', 'google', 'yandex', etc.
    provider_id VARCHAR(255) NOT NULL,  -- ID от провайдера
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(provider, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_user_providers_provider_id ON user_providers(provider, provider_id);

CREATE INDEX IF NOT EXISTS idx_user_providers_user_id ON user_providers(user_id);


INSERT INTO user_providers (user_id, provider, provider_id, created_at)
SELECT id, provider, provider_id, created_at
FROM users
WHERE provider IS NOT NULL AND provider_id IS NOT NULL
ON CONFLICT (provider, provider_id) DO NOTHING;

ALTER TABLE users DROP COLUMN IF EXISTS provider;
ALTER TABLE users DROP COLUMN IF EXISTS provider_id;

COMMENT ON TABLE user_providers IS 'Связь пользователей с OAuth провайдерами (один пользователь - много провайдеров)';


ALTER TABLE users ADD COLUMN IF NOT EXISTS provider VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS provider_id VARCHAR(255);

UPDATE users u
SET provider = up.provider,
    provider_id = up.provider_id
FROM (
    SELECT DISTINCT ON (user_id) user_id, provider, provider_id
    FROM user_providers
    ORDER BY user_id, created_at DESC
) up
WHERE u.id = up.user_id;

DROP TABLE IF EXISTS user_providers;
