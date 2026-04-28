/**
 * Zenvra API client — all fetch calls go through here.
 * Full implementation tracked in issue #8.
 */

const BASE_URL = (import.meta.env.PUBLIC_API_URL || 'http://localhost:8080').replace(/\/$/, '');

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

/**
 * Start a scan and stream results via SSE.
 *
 * Step 1: POST to /api/v1/scan to get a scan_id.
 * Step 2: Open an EventSource on /api/v1/scan/:id/events to receive findings.
 *
 * @param req - Scan request payload.
 * @param onFinding - Called for each finding as it arrives.
 * @param onProgress - Optional callback for progress events.
 * @returns Resolves with all findings once the scan completes.
 */
export async function scan(
  req: ScanRequest,
  onFinding?: (finding: Finding) => void,
  onProgress?: (percentage: number, message: string) => void
): Promise<Finding[]> {
  // Step 1: initiate the scan
  const res = await fetch(`${BASE_URL}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req)
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Scan failed: ${errorText || res.statusText}`);
  }
  const { scan_id } = (await res.json()) as { scan_id: string };

  // Step 2: consume the SSE stream
  return new Promise<Finding[]>((resolve, reject) => {
    const findings: Finding[] = [];
    const es = new EventSource(`${BASE_URL}/api/v1/scan/${scan_id}/events`);

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as {
          type: string;
          data: unknown;
        };
        switch (data.type) {
          case 'finding':
            findings.push(data.data as Finding);
            onFinding?.(data.data as Finding);
            break;
          case 'progress': {
            const p = data.data as { percentage: number; message: string };
            onProgress?.(p.percentage, p.message);
            break;
          }
          case 'complete':
            es.close();
            resolve(findings);
            break;
          case 'error':
            es.close();
            reject(new Error(String(data.data)));
            break;
        }
      } catch {
        // ignore malformed events
      }
    };

    es.onerror = () => {
      es.close();
      // If we already received a complete event this won't fire; only reject
      // if we have no findings yet (genuine connection failure).
      reject(new Error('SSE connection failed'));
    };
  });
}

/**
 * Fetch the persisted findings for a completed scan.
 */
export async function getScanResults(scanId: string): Promise<Finding[]> {
  const res = await fetch(`${BASE_URL}/api/v1/scan/${encodeURIComponent(scanId)}/results`);
  if (!res.ok) throw new Error('Failed to fetch scan results');
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
 * Aggregate statistics derived from scan history.
 */
export interface DashboardStats {
  totalScans: number;
  totalFindings: number;
  criticalCount: number;
  recentScans: ScanHistory[];
}

/**
 * Trigger a manual synchronization with vulnerability databases.
 */
export async function triggerSync(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${BASE_URL}/api/v1/sync`, { method: 'POST' });
  if (!res.ok) throw new Error('Synchronization failed');
  return res.json();
}

/**
 * Fetch available models for a given AI provider.
 */
export async function fetchAiModels(provider: string, apiKey: string, endpoint?: string): Promise<string[]> {
  const res = await fetch(`${BASE_URL}/api/v1/ai/models`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      provider, 
      api_key: apiKey, 
      endpoint: endpoint || null 
    })
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || "Failed to fetch models");
  }
  return res.json();
}
