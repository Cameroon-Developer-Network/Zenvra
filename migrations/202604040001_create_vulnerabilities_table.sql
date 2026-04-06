-- Enable the trgm extension for fast text search
CREATE EXTENSION IF NOT EXISTS pg_trgm;
-- Enable pgcrypto for gen_random_uuid
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create vulnerabilities table for storing CVE and OSV data
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(50) UNIQUE,
    cwe_id VARCHAR(50),
    severity VARCHAR(20) NOT NULL, -- critical, high, medium, low, info
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    published_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_modified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    data_source VARCHAR(50) NOT NULL, -- nvd, osv, github
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast lookup by CVE ID
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
-- Index for filtering by severity
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
-- Index for search
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_title_trgm ON vulnerabilities USING gin (title gin_trgm_ops);
