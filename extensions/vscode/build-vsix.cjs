const { execSync } = require('child_process');
const { File } = require('buffer');

// Polyfill File global for Node 18 (required by modern undici used in vsce)
if (typeof global.File === 'undefined') {
    global.File = File;
}

console.log('--- Compiling TypeScript ---');
execSync('pnpm compile', { stdio: 'inherit' });

console.log('--- Packaging Extension ---');
try {
    // We use the programmatic entry point of vsce to ensure it runs in THIS process with the polyfill
    const vsce = require('@vscode/vsce/out/main');
    
    // main(['package'])
    vsce.main(['package', '--no-git-check', '-o', 'zenvra-0.1.1-rc.2.vsix']).then(() => {
        console.log('VSIX Generated successfully!');
    }).catch(err => {
        console.error('Packaging failed:', err);
        process.exit(1);
    });
} catch (e) {
    console.error('Failed to load vsce:', e);
    process.exit(1);
}
