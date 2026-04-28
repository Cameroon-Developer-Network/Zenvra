-- Add ecosystem and package_name to vulnerabilities table for OSV support
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ecosystem VARCHAR(50);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS package_name TEXT;

-- Index for fast lookup by ecosystem and package (common for SCA)
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_ecosystem_package ON vulnerabilities(ecosystem, package_name);
