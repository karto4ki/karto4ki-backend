ALTER TABLE cards
ADD COLUMN IF NOT EXISTS error_count INT DEFAULT 0;

ALTER TABLE cards
ADD COLUMN IF NOT EXISTS last_rating INT DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_cards_error_count
ON cards(set_id, error_count DESC)
WHERE status IN ('new', 'learning', 'reviewing');

CREATE INDEX IF NOT EXISTS idx_cards_last_rating
ON cards(set_id, last_rating ASC, next_review ASC)
WHERE status IN ('new', 'learning', 'reviewing');
