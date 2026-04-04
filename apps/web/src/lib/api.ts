/**
 * Zenvra API client — all fetch calls go through here.
 * Full implementation tracked in issue #8.
 */

const BASE_URL = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:8080';

export interface AiConfig {
  provider: string;
  api_key: string;
  model: string;
}

export interface ScanRequest {
  code: string;
  language?: string;
  engines?: string[];
  ai_config?: AiConfig;
}

export interface Finding {
  id: string;
  engine: 'sast' | 'sca' | 'secrets' | 'ai_code';
  cve_id?: string;
  cwe_id?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description?: string;
  explanation: string;
  vulnerable_code: string;
  fixed_code: string;
  line_start: number;
  line_end: number;
  file_path?: string;
  detected_at: string;
}

export interface ScanHistory {
  id: string;
  language: string;
  target_name?: string;
  findings_count: number;
  severity_counts: Record<string, number>;
  created_at: string;
}

export async function scan(req: ScanRequest): Promise<Finding[]> {
  const res = await fetch(`${BASE_URL}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req)
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Scan failed: ${errorText || res.statusText}`);
  }
  return res.json();
}

/**
 * Fetch the 50 most recent scans from history.
 */
export async function getHistory(): Promise<ScanHistory[]> {
  const res = await fetch(`${BASE_URL}/api/v1/history`);
  if (!res.ok) throw new Error('Failed to fetch scan history');
  return res.json();
}

/**
 * Trigger a manual synchronization with vulnerability databases.
 */
export async function triggerSync(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${BASE_URL}/api/v1/sync`, { method: 'POST' });
  if (!res.ok) throw new Error('Synchronization failed');
  return res.json();
}
