import * as vscode from 'vscode';

export class SidebarProvider implements vscode.WebviewViewProvider {
  _view?: vscode.WebviewView;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    webviewView.webview.onDidReceiveMessage(async (data) => {
      console.log('Sidebar received message:', data.type);
      switch (data.type) {
        case 'onScan': {
          vscode.commands.executeCommand('zenvra.scanFile');
          break;
        }
        case 'onScanWorkspace': {
          vscode.commands.executeCommand('zenvra.scanWorkspace');
          break;
        }
        case 'onSettings': {
          vscode.commands.executeCommand('workbench.action.openSettings', 'zenvra');
          break;
        }
        case 'onInfo': {
          if (!data.value) return;
          vscode.window.showInformationMessage(data.value);
          break;
        }
      }
    });
  }

  public revive(panel: vscode.WebviewView) {
    this._view = panel;
  }

  public postMessage(message: unknown) {
    if (this._view) {
      this._view.webview.postMessage(message);
    }
  }

  private _getHtmlForWebview(webview: vscode.Webview) {
    const nonce = getNonce();

    return `<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
				<title>Zenvra</title>
                <style>
                    body { 
                        padding: 15px; 
                        color: var(--vscode-foreground);
                        font-family: var(--vscode-font-family);
                        overflow-x: hidden;
                    }
                    .container {
                        display: flex;
                        flex-direction: column;
                        gap: 12px;
                    }
                    .header {
                        display: flex;
                        align-items: center;
                        gap: 10px;
                        margin-bottom: 5px;
                    }
                    .logo {
                        width: 24px;
                        height: 24px;
                        color: #7c3aed;
                    }
                    .title {
                        font-size: 14px;
                        font-weight: bold;
                        margin: 0;
                    }
                    .btn { 
                        background: #7c3aed; 
                        color: white; 
                        border: none; 
                        padding: 8px 16px; 
                        border-radius: 6px; 
                        cursor: pointer; 
                        width: 100%;
                        font-weight: bold;
                        font-size: 11px;
                        transition: all 0.2s;
                    }
                    .btn:hover { background: #6d28d9; }
                    .btn-secondary {
                        background: transparent;
                        border: 1px solid #7c3aed;
                        color: #7c3aed;
                        margin-top: 8px;
                    }
                    .btn-secondary:hover {
                        background: #7c3aed1a;
                    }
                    .btn:disabled { opacity: 0.5; cursor: not-allowed; }

                    /* Progress UI */
                    #progress-container {
                        display: none;
                        padding: 10px;
                        background: var(--vscode-textBlockQuote-background);
                        border-radius: 6px;
                        margin-bottom: 10px;
                    }
                    .progress-bar-bg {
                        height: 4px;
                        background: var(--vscode-editor-inactiveSelectionBackground);
                        border-radius: 2px;
                        margin-top: 8px;
                        overflow: hidden;
                    }
                    #progress-bar-fill {
                        height: 100%;
                        background: #7c3aed;
                        width: 0%;
                        transition: width 0.3s;
                    }
                    #progress-status {
                        font-size: 10px;
                        opacity: 0.8;
                    }

                    /* Findings */
                    #findings-list {
                        display: flex;
                        flex-direction: column;
                        gap: 8px;
                        margin-top: 10px;
                    }
                    .finding-item {
                        padding: 8px;
                        background: var(--vscode-welcomePage-tileBackground);
                        border-radius: 6px;
                        border-left: 3px solid #7c3aed;
                        font-size: 11px;
                    }
                    .finding-severity {
                        font-size: 9px;
                        font-weight: bold;
                        text-transform: uppercase;
                        margin-bottom: 4px;
                        display: block;
                    }
                    .severity-critical { color: #f87171; }
                    .severity-high { color: #fb923c; }
                    .severity-medium { color: #facc15; }
                </style>
			</head>
			<body>
				<div class="container">
                    <div class="header">
                        <svg class="logo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>
                        </svg>
                        <h2 class="title">Zenvra Scanner</h2>
                    </div>

                    <button class="btn" id="scan-btn">SCAN CURRENT FILE</button>
                    <button class="btn btn-secondary" id="scan-ws-btn">SCAN WORKSPACE</button>

                    <div id="progress-container">
                        <div id="progress-status">Initializing...</div>
                        <div class="progress-bar-bg">
                            <div id="progress-bar-fill"></div>
                        </div>
                    </div>

                    <div id="findings-list"></div>
                </div>
                
                <script nonce="${nonce}">
                    const vscode = acquireVsCodeApi();
                    const scanBtn = document.getElementById('scan-btn');
                    const scanWsBtn = document.getElementById('scan-ws-btn');
                    const progressContainer = document.getElementById('progress-container');
                    const progressBar = document.getElementById('progress-bar-fill');
                    const progressStatus = document.getElementById('progress-status');
                    const findingsList = document.getElementById('findings-list');

                    scanBtn.addEventListener('click', () => {
                        findingsList.innerHTML = '';
                        vscode.postMessage({ type: 'onScan' });
                    });

                    scanWsBtn.addEventListener('click', () => {
                        findingsList.innerHTML = '';
                        vscode.postMessage({ type: 'onScanWorkspace' });
                    });

                    window.addEventListener('message', event => {
                        const message = event.data;
                        switch (message.type) {
                            case 'progress':
                                if (message.data) {
                                    progressContainer.style.display = 'block';
                                    scanBtn.disabled = true;
                                    scanWsBtn.disabled = true;
                                    progressBar.style.width = (message.data.percentage || 0) + '%';
                                    progressStatus.innerText = message.data.message || 'Processing...';
                                }
                                break;
                            case 'finding':
                                if (message.data) {
                                    const item = document.createElement('div');
                                    item.className = 'finding-item';
                                    const severity = message.data.severity || 'info';
                                    const sevClass = 'severity-' + severity.toLowerCase();
                                    item.innerHTML = '<span class="finding-severity ' + sevClass + '">' + severity + '</span>' +
                                                    '<strong>' + (message.data.title || 'Vulnerability detected') + '</strong>';
                                    findingsList.appendChild(item);
                                }
                                break;
                            case 'complete':
                                progressContainer.style.display = 'none';
                                scanBtn.disabled = false;
                                scanWsBtn.disabled = false;
                                if (findingsList.innerHTML === '') {
                                    findingsList.innerHTML = '<div style="font-size: 10px; opacity: 0.5; text-align: center;">No issues found</div>';
                                }
                                break;
                        }
                    });
                </script>
			</body>
			</html>`;
  }
}

function getNonce() {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
