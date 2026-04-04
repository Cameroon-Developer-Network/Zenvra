import * as vscode from 'vscode';
import { Finding, ScanRequest } from './types';

const DIAGNOSTIC_SOURCE = 'Zenvra';
const diagnosticCollection = vscode.languages.createDiagnosticCollection('zenvra');

export function activate(context: vscode.ExtensionContext): void {
  console.log('Zenvra extension activated');

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
  vscode.window.showInformationMessage('Zenvra: Workspace scan coming in v0.2.');
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

  vscode.window.setStatusBarMessage('$(sync~spin) Zenvra: Scanning...', 2000);

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

    const findings = (await response.json()) as Finding[];
    updateDiagnostics(document, findings);
    
    const count = findings.length;
    if (count === 0) {
      vscode.window.setStatusBarMessage('$(shield) Zenvra: No issues found', 3000);
    } else {
      vscode.window.setStatusBarMessage(`$(warning) Zenvra: Found ${count} issue(s)`, 3000);
    }
  } catch (err: any) {
    vscode.window.showErrorMessage(`Zenvra Scan Failed: ${err.message}`);
    vscode.window.setStatusBarMessage('$(error) Zenvra: Scan failed', 3000);
  }
}

function updateDiagnostics(document: vscode.TextDocument, findings: Finding[]): void {
  const diagnostics: vscode.Diagnostic[] = findings.map((f) => {
    // VS Code lines are 0-indexed, Zenvra is 1-indexed (standard terminal behavior)
    const line = Math.max(0, f.line_start - 1);
    const range = new vscode.Range(line, 0, line, 0); // TODO: improve range mapping

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

  diagnosticCollection.set(document.uri, diagnostics);
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
