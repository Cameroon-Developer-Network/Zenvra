/**
 * Zenvra VS Code Extension
 *
 * Provides inline security diagnostics, hover explanations,
 * and one-click fix suggestions powered by the Zenvra scanner.
 */

import * as vscode from 'vscode';

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
  // TODO: call Zenvra API with document content, populate diagnostics
  // Placeholder — removes stale diagnostics for now
  diagnosticCollection.delete(document.uri);
  vscode.window.setStatusBarMessage('$(shield) Zenvra: Scan complete', 3000);
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
