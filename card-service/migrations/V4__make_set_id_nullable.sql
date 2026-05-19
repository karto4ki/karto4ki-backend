-- Make set_id nullable in study_sessions for "all sets" study mode

ALTER TABLE study_sessions 
ALTER COLUMN set_id DROP NOT NULL;

-- Update existing sessions with empty set_id to NULL (if any)
UPDATE study_sessions 
SET set_id = NULL 
WHERE set_id = '00000000-0000-0000-0000-000000000000';
