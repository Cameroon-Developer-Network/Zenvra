/**
 * Zenvra API client — all fetch calls go through here.
 * Full implementation tracked in issue #8.
 */

const BASE_URL = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:3001';

export interface ScanRequest {
  code: string;
  language?: string;
  filename?: string;
}

export interface Finding {
  id: string;
  kind: 'sast' | 'sca' | 'secret';
  file: string;
  line?: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cve_id?: string;
  title: string;
  description: string;
  explanation?: string;
  fix_code?: string;
}

export interface ScanResult {
  scan_id: string;
  findings: Finding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    files_scanned: number;
    duration_ms: number;
  };
}

export async function scan(req: ScanRequest): Promise<ScanResult> {
  const res = await fetch(`${BASE_URL}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req)
  });
  if (!res.ok) throw new Error(`Scan failed: ${res.statusText}`);
  return res.json();
}
