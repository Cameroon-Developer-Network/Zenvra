-- Add explanation column to store AI-generated plain-English explanation for each finding
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS explanation TEXT;
