-- Миграция для публичных профилей и счётчиков
-- V2__public_profiles.sql

-- Добавить счётчики для пользователей (публичные наборы, просмотры, подписчики)
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS public_sets_count INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_views INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS followers_count INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS following_count INT DEFAULT 0;

-- Индексы для быстрого поиска
CREATE INDEX IF NOT EXISTS idx_users_public_sets ON users(public_sets_count DESC);
CREATE INDEX IF NOT EXISTS idx_users_followers ON users(followers_count DESC);

-- Таблица подписок (пользователи могут подписываться на других)
CREATE TABLE IF NOT EXISTS user_follows (
    follower_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (follower_id, following_id),
    CONSTRAINT chk_different_users CHECK (follower_id != following_id)
);

CREATE INDEX IF NOT EXISTS idx_user_follows_follower ON user_follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_following ON user_follows(following_id);

-- Триггер для обновления счётчиков подписчиков
CREATE OR REPLACE FUNCTION update_user_follow_counts()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE users SET followers_count = followers_count + 1 WHERE id = NEW.following_id;
        UPDATE users SET following_count = following_count + 1 WHERE id = NEW.follower_id;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE users SET followers_count = followers_count - 1 WHERE id = OLD.following_id;
        UPDATE users SET following_count = following_count - 1 WHERE id = OLD.follower_id;
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_follow_counts
AFTER INSERT OR DELETE ON user_follows
FOR EACH ROW EXECUTE FUNCTION update_user_follow_counts();

-- Функция для обновления счётчика публичных наборов (вызывается из card-service через RPC или триггер)
CREATE OR REPLACE FUNCTION update_user_public_sets_count(user_uuid UUID, delta INT)
RETURNS void AS $$
BEGIN
    UPDATE users 
    SET public_sets_count = public_sets_count + delta 
    WHERE id = user_uuid;
END;
$$ LANGUAGE plpgsql;
