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

  private _getHtmlForWebview(webview: vscode.Webview) {
    return `<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Zenvra</title>
                <style>
                    body { 
                        padding: 20px; 
                        color: var(--vscode-foreground);
                        font-family: var(--vscode-font-family);
                    }
                    .container {
                        display: flex;
                        flex-direction: column;
                        gap: 15px;
                        align-items: center;
                        text-align: center;
                    }
                    .logo-container {
                        width: 64px;
                        height: 64px;
                        margin-bottom: 10px;
                        filter: drop-shadow(0 0 8px rgba(124, 58, 237, 0.3));
                    }
                    .title {
                        font-size: 18px;
                        font-weight: bold;
                        margin: 0;
                        color: var(--vscode-editor-foreground);
                    }
                    .subtitle {
                        font-size: 11px;
                        opacity: 0.7;
                        letter-spacing: 0.1em;
                        text-transform: uppercase;
                        margin-top: -5px;
                    }
                    .btn { 
                        background: #7c3aed; 
                        color: white; 
                        border: none; 
                        padding: 10px 20px; 
                        border-radius: 8px; 
                        cursor: pointer; 
                        width: 100%;
                        font-weight: bold;
                        font-size: 12px;
                        transition: all 0.2s;
                        box-shadow: 0 4px 12px rgba(124, 58, 237, 0.2);
                    }
                    .btn:hover { 
                        background: #6d28d9; 
                        transform: translateY(-1px);
                        box-shadow: 0 6px 16px rgba(124, 58, 237, 0.3);
                    }
                    .btn:active {
                        transform: translateY(0);
                    }
                    .btn-secondary {
                        background: transparent;
                        border: 1px solid var(--vscode-button-secondaryBackground);
                        color: var(--vscode-foreground);
                        margin-top: 5px;
                    }
                    .divider {
                        height: 1px;
                        background: var(--vscode-divider);
                        width: 100%;
                        margin: 10px 0;
                    }
                    .card {
                        background: var(--vscode-welcomePage-tileBackground);
                        border-radius: 8px;
                        padding: 12px;
                        width: 100%;
                        font-size: 10px;
                        text-align: left;
                    }
                    .card-title {
                        font-weight: bold;
                        margin-bottom: 4px;
                        display: block;
                    }
                </style>
			</head>
			<body>
				<div class="container">
                    <div class="logo-container">
                        <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" fill="#7C3AED" fill-opacity="0.2" stroke="#7C3AED" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M12 8V12" stroke="#7C3AED" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M12 16H12.01" stroke="#7C3AED" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </div>
                    <h2 class="title">Zenvra</h2>
                    <span class="subtitle">Security Scanner</span>
                    
                    <div class="divider"></div>

                    <button class="btn" id="scan-btn">SCAN CURRENT FILE</button>
                    
                    <div class="card">
                        <span class="card-title">PROTECTION STATUS</span>
                        AI-powered diagnostics are active. Scan results will appear inline as diagnostics.
                    </div>

                    <button class="btn btn-secondary" id="settings-btn">Extension Settings</button>
                </div>
                
                <script>
                    const vscode = acquireVsCodeApi();
                    document.getElementById('scan-btn').addEventListener('click', () => {
                        vscode.postMessage({ type: 'onScan' });
                    });
                    document.getElementById('settings-btn').addEventListener('click', () => {
                        vscode.postMessage({ type: 'onSettings' });
                    });
                </script>
			</body>
			</html>`;
  }
}
