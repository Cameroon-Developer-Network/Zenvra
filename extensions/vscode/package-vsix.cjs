const { execSync } = require('child_process');
// Polyfill File for undici in Node 18
if (typeof global.File === 'undefined') {
    global.File = class File extends Blob {
        constructor(blobParts, fileName, options = {}) {
            super(blobParts, options);
            this.name = fileName;
            this.lastModified = options.lastModified || Date.now();
        }
    };
}

console.log('Starting compilation...');
execSync('pnpm compile', { stdio: 'inherit' });

console.log('Starting packaging...');
try {
    // Try to run vsce via npx
    execSync('npx -y @vscode/vsce package --no-git-check', { 
        stdio: 'inherit',
        env: { ...process.env, NODE_OPTIONS: '--no-warnings' }
    });
} catch (e) {
    console.error('Packaging failed, trying fallback...');
    // Fallback to local vsce if available
    execSync('./node_modules/.bin/vsce package --no-git-check', { stdio: 'inherit' });
}
