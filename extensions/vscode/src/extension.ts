import * as vscode from 'vscode';
import { Finding, ScanRequest, WorkspaceFile, WorkspaceScanRequest } from './types';
import { SidebarProvider } from './sidebarProvider';

const DIAGNOSTIC_SOURCE = 'Zenvra';
const diagnosticCollection = vscode.languages.createDiagnosticCollection('zenvra');
let sidebarProvider: SidebarProvider;
let debounceTimer: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext): void {
  console.log('Zenvra extension activated');

  sidebarProvider = new SidebarProvider(context.extensionUri);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider('zenvraMain', sidebarProvider)
  );

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('zenvra.scanFile', () => scanCurrentFile()),
    vscode.commands.registerCommand('zenvra.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('zenvra.setApiToken', () => setApiToken(context)),
    diagnosticCollection,
  );

  // Auto-scan on save if enabled
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('zenvra');
      if (config.get<boolean>('scanOnSave')) {
        scanDocument(doc);
      }
    }),
  );

  // Real-time scan on type if enabled (with debounce)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const config = vscode.workspace.getConfiguration('zenvra');
      if (config.get<boolean>('scanOnType')) {
        if (debounceTimer) {
          clearTimeout(debounceTimer);
        }
        debounceTimer = setTimeout(() => {
          scanDocument(event.document);
        }, 1500);
      }
    })
  );
}

export function deactivate(): void {
  diagnosticCollection.clear();
}

async function scanCurrentFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('Zenvra: No active file to scan.');
    return;
  }
  await scanDocument(editor.document);
}

async function scanWorkspace(): Promise<void> {
  const config = vscode.workspace.getConfiguration('zenvra');
  const apiUrl = config.get<string>('apiUrl') || 'http://localhost:8080';
  const aiProvider = config.get<string>('aiProvider');
  const aiApiKey = config.get<string>('aiApiKey');
  const aiModel = config.get<string>('aiModel');
  const aiEndpoint = config.get<string>('aiEndpoint');

  // 1. Find all supported files
  vscode.window.setStatusBarMessage('$(sync~spin) Zenvra: Collecting files...', 2000);
  
  // Supported extensions from CLI main.rs
  const supportedExtensions = [
    'py', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'rs', 'go', 'java',
    'cs', 'cpp', 'cc', 'c', 'h', 'rb', 'php', 'swift', 'kt', 'kts',
    'yaml', 'yml', 'toml', 'json', 'xml', 'env', 'sh', 'bash', 'zsh',
    'dockerfile', 'svelte', 'vue'
  ];
  
  const globPattern = `**/*.{${supportedExtensions.join(',')}}`;
  const excludePattern = '{**/node_modules/**,**/target/**,**/.git/**,**/dist/**,**/build/**}';
  
  const files = await vscode.workspace.findFiles(globPattern, excludePattern, 100); // Limit to 100 for now
  
  if (files.length === 0) {
    vscode.window.showInformationMessage('Zenvra: No scannable files found in workspace.');
    return;
  }

  const workspaceFiles: WorkspaceFile[] = await Promise.all(
    files.map(async (uri) => {
      const content = await vscode.workspace.fs.readFile(uri);
      const relativePath = vscode.workspace.asRelativePath(uri);
      const ext = relativePath.split('.').pop() || 'js';
      
      return {
        path: relativePath,
        code: Buffer.from(content).toString('utf8'),
        language: ext
      };
    })
  );

  const scanRequest: WorkspaceScanRequest = {
    files: workspaceFiles,
    engines: config.get<string[]>('engines'),
  };

  if (aiProvider && aiApiKey) {
    scanRequest.aiConfig = {
      provider: aiProvider,
      apiKey: aiApiKey,
      model: aiModel || 'default',
      endpoint: aiEndpoint || undefined,
    };
  }

  try {
    const response = await fetch(`${apiUrl}/api/v1/scan/workspace`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(scanRequest),
    });

    if (!response.ok) {
      const errorMsg = await response.text();
      throw new Error(errorMsg || response.statusText);
    }

    const { scan_id } = (await response.json()) as { scan_id: string };
    
    // Subscribe to SSE stream
    const sseResponse = await fetch(`${apiUrl}/api/v1/scan/${scan_id}/events`);
    const body = sseResponse.body;
    if (!body) throw new Error('Failed to connect to event stream');

    const reader = (body as any).getReader();
    const decoder = new TextDecoder();
    const allFindings: Record<string, Finding[]> = {};

    sidebarProvider.postMessage({ type: 'progress', data: { message: `Scanning ${files.length} files...`, percentage: 10 } });

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value, { stream: true });
      const lines = chunk.split('\n');

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const event = JSON.parse(line.slice(6));
            
            switch (event.type) {
              case 'progress':
                vscode.window.setStatusBarMessage(`$(sync~spin) Zenvra: ${event.data.message}`, 2000);
                sidebarProvider.postMessage({ type: 'progress', data: event.data });
                break;
              case 'finding': {
                const finding = event.data as Finding;
                const filePath = finding.file_path || 'unknown';
                if (!allFindings[filePath]) {
                  allFindings[filePath] = [];
                }
                allFindings[filePath].push(finding);
                
                // Update diagnostics for this specific file
                const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
                if (workspaceFolder) {
                    const fileUri = vscode.Uri.joinPath(workspaceFolder.uri, filePath);
                    updateDiagnosticsForUri(fileUri, allFindings[filePath]);
                }
                
                sidebarProvider.postMessage({ type: 'finding', data: finding });
                break;
              }
              case 'complete': {
                const totalCount = Object.values(allFindings).flat().length;
                vscode.window.setStatusBarMessage(`$(shield) Zenvra: Workspace scan complete (${totalCount} issues)`, 5000);
                sidebarProvider.postMessage({ type: 'complete' });
                return;
              }
              case 'error':
                throw new Error(event.data);
            }
          } catch (e) {
            console.error('Error parsing SSE event:', e);
          }
        }
      }
    }
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`Zenvra Workspace Scan Failed: ${errorMsg}`);
  }
}

async function scanDocument(document: vscode.TextDocument): Promise<void> {
  const config = vscode.workspace.getConfiguration('zenvra');
  const apiUrl = config.get<string>('apiUrl') || 'http://localhost:8080';
  const aiProvider = config.get<string>('aiProvider');
  const aiApiKey = config.get<string>('aiApiKey');
  const aiModel = config.get<string>('aiModel');
  const aiEndpoint = config.get<string>('aiEndpoint');

  const scanRequest: ScanRequest = {
    code: document.getText(),
    language: document.languageId,
    engines: config.get<string[]>('engines'),
  };

  // Add AI config if provider and key are present
  if (aiProvider && aiApiKey) {
    scanRequest.aiConfig = {
      provider: aiProvider,
      apiKey: aiApiKey,
      model: aiModel || 'default',
      endpoint: aiEndpoint || undefined,
    };
  }

  vscode.window.setStatusBarMessage('$(sync~spin) Zenvra: Initializing...', 2000);

  try {
    const response = await fetch(`${apiUrl}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(scanRequest),
    });

    if (!response.ok) {
      const errorMsg = await response.text();
      throw new Error(errorMsg || response.statusText);
    }

    const { scan_id } = (await response.json()) as { scan_id: string };
    
    // Subscribe to SSE stream
    const sseResponse = await fetch(`${apiUrl}/api/v1/scan/${scan_id}/events`);
    const body = sseResponse.body;
    if (!body) throw new Error('Failed to connect to event stream');

    const reader = (body as any).getReader();
    const decoder = new TextDecoder();
    const findings: Finding[] = [];

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value, { stream: true });
      const lines = chunk.split('\n');

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const event = JSON.parse(line.slice(6));
            
            switch (event.type) {
              case 'progress':
                vscode.window.setStatusBarMessage(`$(sync~spin) Zenvra: ${event.data.message}`, 2000);
                // Also notify sidebar
                sidebarProvider.postMessage({ type: 'progress', data: event.data });
                break;
              case 'finding':
                findings.push(event.data);
                updateDiagnostics(document, findings);
                sidebarProvider.postMessage({ type: 'finding', data: event.data });
                break;
              case 'complete': {
                const count = findings.length;
                if (count === 0) {
                  vscode.window.setStatusBarMessage('$(shield) Zenvra: No issues found', 3000);
                } else {
                  vscode.window.setStatusBarMessage(`$(warning) Zenvra: Found ${count} issue(s)`, 3000);
                }
                sidebarProvider.postMessage({ type: 'complete' });
                return;
              }
              case 'error':
                throw new Error(event.data);
            }
          } catch (e) {
            console.error('Error parsing SSE event:', e);
          }
        }
      }
    }
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`Zenvra Scan Failed: ${errorMsg}`);
    vscode.window.setStatusBarMessage('$(error) Zenvra: Scan failed', 3000);
  }
}

function updateDiagnostics(document: vscode.TextDocument, findings: Finding[]): void {
  updateDiagnosticsForUri(document.uri, findings);
}

function updateDiagnosticsForUri(uri: vscode.Uri, findings: Finding[]): void {
  const config = vscode.workspace.getConfiguration('zenvra');
  const minSeverity = config.get<string>('minSeverity') || 'medium';

  const severityOrder: Record<string, number> = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };
  const minLevel = severityOrder[minSeverity.toLowerCase()] ?? 2;

  const filtered = findings.filter(
    (f) => (severityOrder[f.severity.toLowerCase()] ?? 0) >= minLevel
  );

  const diagnostics: vscode.Diagnostic[] = filtered.map((f) => {
    // VS Code lines are 0-indexed, Zenvra is 1-indexed
    const line = Math.max(0, f.line_start - 1);
    const range = new vscode.Range(line, 0, line, 500); // 500 to cover most lines

    let severity = vscode.DiagnosticSeverity.Warning;
    if (f.severity === 'critical' || f.severity === 'high') {
      severity = vscode.DiagnosticSeverity.Error;
    } else if (f.severity === 'info') {
      severity = vscode.DiagnosticSeverity.Information;
    }

    const d = new vscode.Diagnostic(
      range,
      `[${f.engine.toUpperCase()}] ${f.title}\n\n${f.explanation}\n\nFix Recommendation:\n${f.fixed_code}`,
      severity
    );
    d.source = DIAGNOSTIC_SOURCE;
    if (f.cve_id) {
       d.code = f.cve_id;
    }
    return d;
  });

  diagnosticCollection.set(uri, diagnostics);
}

async function setApiToken(context: vscode.ExtensionContext): Promise<void> {
  const token = await vscode.window.showInputBox({
    prompt: 'Paste your Zenvra API token from zenvra.dev/settings',
    password: true,
    placeHolder: 'zenvra_...',
  });
  if (token) {
    await context.secrets.store('zenvra.apiToken', token);
    vscode.window.showInformationMessage('Zenvra: API token saved.');
  }
}
