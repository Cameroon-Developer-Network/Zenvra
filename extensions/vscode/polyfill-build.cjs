const { File, Blob } = require('buffer');
// Polyfill File for Node 18 contexts (undici/fetch compatibility)
if (typeof global.File === 'undefined') {
    global.File = File;
}
if (typeof global.Blob === 'undefined') {
    global.Blob = Blob;
}
