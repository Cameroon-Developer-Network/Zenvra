import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scan, getHistory, getScanResults, fetchAiModels, triggerSync } from './api';

// ── Helpers ──────────────────────────────────────────────────────────────────

const mockFinding = {
  id: 'test-id-1',
  engine: 'secrets' as const,
  severity: 'high' as const,
  title: 'Hardcoded AWS Key',
  explanation: 'AWS access key detected.',
  vulnerable_code: 'key = "AKIAIOSFODNN7EXAMPLE"',
  fixed_code: 'key = os.environ.get("AWS_ACCESS_KEY_ID")',
  line_start: 1,
  line_end: 1,
  detected_at: new Date().toISOString(),
};

const mockHistory = [
  {
    id: 'scan-abc',
    language: 'python',
    target_name: 'Manual Scan',
    findings_count: 3,
    severity_counts: { high: 2, medium: 1 },
    created_at: new Date().toISOString(),
  },
];

// ── Mock SSE helper ──────────────────────────────────────────────────────────

/** Create a mock EventSource that fires a sequence of messages then closes. */
function createMockEventSource(events: { type: string; data: unknown }[]) {
  return class MockEventSource {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSED = 2;
    readyState = 1;
    onmessage: ((ev: MessageEvent) => void) | null = null;
    onerror: ((ev: Event) => void) | null = null;

    constructor() {
      // Schedule events asynchronously so callers have time to set handlers.
      Promise.resolve().then(() => {
        for (const event of events) {
          this.onmessage?.({
            data: JSON.stringify(event),
          } as MessageEvent);
        }
      });
    }

    close() {
      this.readyState = MockEventSource.CLOSED;
    }
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('scan()', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('initiates a scan and resolves with findings from the SSE stream', async () => {
    const scanId = 'test-scan-id';

    // Mock POST /api/v1/scan → { scan_id }
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ scan_id: scanId }),
    } as Response);

    // Mock EventSource with a complete flow
    vi.stubGlobal(
      'EventSource',
      createMockEventSource([
        { type: 'progress', data: { percentage: 50, message: 'Running...' } },
        { type: 'finding', data: mockFinding },
        { type: 'complete', data: null },
      ])
    );

    const findings = await scan({ code: 'some code', language: 'python', engines: ['secrets'] });

    expect(findings).toHaveLength(1);
    expect(findings[0].title).toBe('Hardcoded AWS Key');
  });

  it('invokes onFinding callback for each finding', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ scan_id: 'x' }),
    } as Response);

    vi.stubGlobal(
      'EventSource',
      createMockEventSource([
        { type: 'finding', data: mockFinding },
        { type: 'complete', data: null },
      ])
    );

    const received: typeof mockFinding[] = [];
    await scan({ code: 'code', language: 'python' }, (f) => received.push(f as typeof mockFinding));

    expect(received).toHaveLength(1);
    expect(received[0].id).toBe(mockFinding.id);
  });

  it('invokes onProgress callback', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ scan_id: 'y' }),
    } as Response);

    vi.stubGlobal(
      'EventSource',
      createMockEventSource([
        { type: 'progress', data: { percentage: 30, message: 'Scanning...' } },
        { type: 'complete', data: null },
      ])
    );

    const progresses: number[] = [];
    await scan({ code: 'code', language: 'python' }, undefined, (pct) => progresses.push(pct));

    expect(progresses).toContain(30);
  });

  it('rejects when the server returns an error event', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ scan_id: 'z' }),
    } as Response);

    vi.stubGlobal(
      'EventSource',
      createMockEventSource([{ type: 'error', data: 'scan failed internally' }])
    );

    await expect(scan({ code: 'code', language: 'python' })).rejects.toThrow(
      'scan failed internally'
    );
  });

  it('throws when the POST request fails', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 422,
      statusText: 'Unprocessable Entity',
      text: async () => 'invalid request',
    } as unknown as Response);

    await expect(scan({ code: '', language: 'python' })).rejects.toThrow('Scan failed');
  });
});

describe('getHistory()', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it('returns an array of scan history records', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => mockHistory,
    } as Response);

    const history = await getHistory();
    expect(history).toHaveLength(1);
    expect(history[0].id).toBe('scan-abc');
    expect(history[0].findings_count).toBe(3);
  });

  it('throws when the server responds with an error', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 500,
    } as Response);

    await expect(getHistory()).rejects.toThrow('Failed to fetch scan history');
  });
});

describe('getScanResults()', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it('fetches findings for a specific scan ID', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => [mockFinding],
    } as Response);

    const results = await getScanResults('scan-abc');
    expect(results).toHaveLength(1);
    expect(results[0].engine).toBe('secrets');
  });

  it('URL-encodes the scan ID', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => [],
    } as Response);

    await getScanResults('scan/with/slashes');
    const calledUrl = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(calledUrl).toContain('scan%2Fwith%2Fslashes');
  });
});

describe('fetchAiModels()', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it('returns a list of model names on success', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ['claude-3-5-sonnet-20241022', 'claude-3-haiku-20240307'],
    } as Response);

    const models = await fetchAiModels('anthropic', 'sk-ant-test');
    expect(models).toHaveLength(2);
    expect(models[0]).toBe('claude-3-5-sonnet-20241022');
  });

  it('throws with the server error message on failure', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      text: async () => 'Invalid API key',
    } as unknown as Response);

    await expect(fetchAiModels('anthropic', 'bad-key')).rejects.toThrow('Invalid API key');
  });
});

describe('triggerSync()', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it('returns success status and message', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ status: 'success', message: 'Synchronization completed' }),
    } as Response);

    const result = await triggerSync();
    expect(result.status).toBe('success');
    expect(result.message).toBe('Synchronization completed');
  });

  it('throws when the sync endpoint fails', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 500,
    } as Response);

    await expect(triggerSync()).rejects.toThrow('Synchronization failed');
  });
});
