// Keep Shipping VS Code extension: `keepshipping lsp` over stdio.
const vscode = require('vscode');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');

let client;

function activate(context) {
  const serverPath = vscode.workspace
    .getConfiguration('keepshipping')
    .get('server.path', 'keepshipping');

  const serverOptions = {
    run: { command: serverPath, args: ['lsp'], transport: TransportKind.stdio },
    debug: {
      command: serverPath,
      args: ['lsp'],
      transport: TransportKind.stdio,
      options: { env: { ...process.env, KEEP_SHIPPING_LOG: 'debug' } },
    },
  };

  const trace = vscode.workspace.getConfiguration('keepshipping').get('trace.server', 'off');
  const clientOptions = {
    documentSelector: [
      { scheme: 'file', language: 'keepshipping' },
      { scheme: 'untitled', language: 'keepshipping' },
    ],
    // vscode-languageclient 10 needs a LogOutputChannel ({ log: true }); a plain
    // OutputChannel has no onDidChangeLogLevel and the client fails to start.
    traceOutputChannel: vscode.window.createOutputChannel('Keep Shipping Language Server', { log: true }),
    initializationOptions: { trace },
  };

  client = new LanguageClient('keepshipping', 'Keep Shipping Language Server', serverOptions, clientOptions);
  context.subscriptions.push(client);

  client.start().catch((error) => {
    client = undefined;
    const message = `Keep Shipping language server failed to start: ${error && error.message ? error.message : error}. ` +
      `Install the \`keepshipping\` CLI or set \`keepshipping.server.path\` to its location.`;
    vscode.window.showErrorMessage(message);
  });
}

function deactivate() {
  return client ? client.stop() : undefined;
}

module.exports = { activate, deactivate };