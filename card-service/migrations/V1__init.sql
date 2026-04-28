-- Таблица наборов карточек
CREATE TABLE IF NOT EXISTS card_sets (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_card_sets_owner_id ON card_sets(owner_id);
CREATE INDEX idx_card_sets_is_public ON card_sets(is_public);
CREATE INDEX idx_card_sets_created_at ON card_sets(created_at);

-- Таблица карточек
CREATE TABLE IF NOT EXISTS cards (
    id UUID PRIMARY KEY,
    set_id UUID NOT NULL REFERENCES card_sets(id) ON DELETE CASCADE,
    front TEXT NOT NULL,
    back TEXT NOT NULL,
    image_url TEXT,
    audio_url TEXT,
    status VARCHAR(20) DEFAULT 'new',
    next_review TIMESTAMP WITH TIME ZONE,
    streak INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_cards_set_id ON cards(set_id);
CREATE INDEX idx_cards_status ON cards(status);
CREATE INDEX idx_cards_next_review ON cards(next_review);

-- Таблица сессий обучения
CREATE TABLE IF NOT EXISTS study_sessions (
    id UUID PRIMARY KEY,
    set_id UUID NOT NULL REFERENCES card_sets(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    session_type VARCHAR(20) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_study_sessions_set_id ON study_sessions(set_id);
CREATE INDEX idx_study_sessions_user_id ON study_sessions(user_id);

-- Таблица истории обучения
CREATE TABLE IF NOT EXISTS study_history (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    set_id UUID NOT NULL REFERENCES card_sets(id) ON DELETE CASCADE,
    cards_studied INT DEFAULT 0,
    time_spent_minutes INT DEFAULT 0,
    study_date DATE DEFAULT CURRENT_DATE,
    UNIQUE(user_id, set_id, study_date)
);

CREATE INDEX idx_study_history_user_id ON study_history(user_id);
CREATE INDEX idx_study_history_study_date ON study_history(study_date);
