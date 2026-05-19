ALTER TABLE users 
ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_users_last_activity ON users(last_activity_at);

UPDATE users 
SET last_activity_at = created_at 
WHERE last_activity_at IS NULL;

COMMENT ON COLUMN users.last_activity_at IS 'Последняя активность пользователя (вход, действия в приложении)';
