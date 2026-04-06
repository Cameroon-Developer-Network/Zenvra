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

  private _getHtmlForWebview(_webview: vscode.Webview) {
    return `<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
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

                    <div id="progress-container">
                        <div id="progress-status">Initializing...</div>
                        <div class="progress-bar-bg">
                            <div id="progress-bar-fill"></div>
                        </div>
                    </div>

                    <div id="findings-list"></div>
                </div>
                
                <script>
                    const vscode = acquireVsCodeApi();
                    const scanBtn = document.getElementById('scan-btn');
                    const progressContainer = document.getElementById('progress-container');
                    const progressBar = document.getElementById('progress-bar-fill');
                    const progressStatus = document.getElementById('progress-status');
                    const findingsList = document.getElementById('findings-list');

                    scanBtn.addEventListener('click', () => {
                        findingsList.innerHTML = '';
                        vscode.postMessage({ type: 'onScan' });
                    });

                    window.addEventListener('message', event => {
                        const message = event.data;
                        switch (message.type) {
                            case 'progress':
                                progressContainer.style.display = 'block';
                                scanBtn.disabled = true;
                                progressBar.style.width = message.data.percentage + '%';
                                progressStatus.innerText = message.data.message;
                                break;
                            case 'finding':
                                const item = document.createElement('div');
                                item.className = 'finding-item';
                                const sevClass = 'severity-' + message.data.severity.toLowerCase();
                                item.innerHTML = \`
                                    <span class="finding-severity \${sevClass}">\${message.data.severity}</span>
                                    <strong>\${message.data.title}</strong>
                                \`;
                                findingsList.appendChild(item);
                                break;
                            case 'complete':
                                progressContainer.style.display = 'none';
                                scanBtn.disabled = false;
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
