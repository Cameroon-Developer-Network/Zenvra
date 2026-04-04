-- Create scans table to store scan metadata
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    language VARCHAR(50) NOT NULL,
    target_name TEXT, -- User-defined name or file name
    findings_count INTEGER DEFAULT 0,
    severity_counts JSONB DEFAULT '{}'::jsonb, -- Store counts by severity (critical, high, etc.)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create scan_results table to store the findings for each scan
CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    engine VARCHAR(50) NOT NULL,
    cve_id VARCHAR(50),
    cwe_id VARCHAR(50),
    severity VARCHAR(20) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    vulnerable_code TEXT NOT NULL,
    fixed_code TEXT,
    line_start INTEGER,
    line_end INTEGER,
    file_path TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast lookup of results by scan
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
-- Index for history sorting
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
