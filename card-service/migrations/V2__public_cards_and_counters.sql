ALTER TABLE cards
ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT FALSE;

ALTER TABLE card_sets
ADD COLUMN IF NOT EXISTS views_count INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS clones_count INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}',
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_card_sets_public_search
ON card_sets(is_public, name, created_at DESC)
WHERE is_public = true;

CREATE INDEX IF NOT EXISTS idx_card_sets_owner_public
ON card_sets(owner_id, is_public)
WHERE is_public = true;

CREATE INDEX IF NOT EXISTS idx_cards_public_search
ON cards(is_public, front, back)
WHERE is_public = true;

CREATE INDEX IF NOT EXISTS idx_cards_set_public
ON cards(set_id, is_public)
WHERE is_public = true;

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_card_sets_updated_at
BEFORE UPDATE ON card_sets
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE IF NOT EXISTS set_views (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    set_id UUID NOT NULL REFERENCES card_sets(id) ON DELETE CASCADE,
    user_id UUID,
    viewed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_set_views_set_id ON set_views(set_id);
CREATE INDEX IF NOT EXISTS idx_set_views_user_id ON set_views(user_id);
CREATE INDEX IF NOT EXISTS idx_set_views_viewed_at ON set_views(viewed_at);

CREATE OR REPLACE FUNCTION update_set_views_count()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE card_sets
    SET views_count = (
        SELECT COUNT(DISTINCT user_id)
        FROM set_views
        WHERE set_id = NEW.set_id
        AND viewed_at > NOW() - INTERVAL '30 days'
    )
    WHERE id = NEW.set_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_set_views_count
AFTER INSERT ON set_views
FOR EACH ROW
EXECUTE FUNCTION update_set_views_count();

CREATE OR REPLACE FUNCTION cleanup_old_set_views()
RETURNS void AS $$
BEGIN
    DELETE FROM set_views WHERE viewed_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;
