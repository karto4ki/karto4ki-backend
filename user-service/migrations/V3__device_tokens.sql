-- Device tokens for push notifications
CREATE TABLE IF NOT EXISTS device_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_type VARCHAR(20) NOT NULL CHECK (device_type IN ('ios', 'android')),
    token VARCHAR(255) NOT NULL,
    app_version VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT unique_device_token UNIQUE(user_id, device_type, token)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_device_tokens_user_id ON device_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_device_tokens_token ON device_tokens(token);

-- Comments
COMMENT ON TABLE device_tokens IS 'Устройства пользователей для push-уведомлений';
COMMENT ON COLUMN device_tokens.device_type IS 'Тип устройства: ios или android';
COMMENT ON COLUMN device_tokens.token IS 'Device token от APNs (iOS) или FCM (Android)';
COMMENT ON COLUMN device_tokens.app_version IS 'Версия приложения, отправившего токен';

-- Trigger для обновления updated_at
CREATE OR REPLACE FUNCTION update_device_token_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER device_tokens_updated_at
    BEFORE UPDATE ON device_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_device_token_updated_at();
