# Keep Shipping for VS Code

Highlighting and language-server support for Keep Shipping site files.

A site file is named `ship.ks` (or `*.ship.ks`). This extension registers those
names and nothing else: `.ks` belongs to Red Hat/Fedora Kickstart, so no grammar
may claim it. See [docs/LANGUAGE.md](../../docs/LANGUAGE.md).

## Language server

Set `keepshipping.server.path` if the `keepshipping` binary is not on `PATH`
(default: `keepshipping`). The extension starts `keepshipping lsp` over stdio.

## Packaging

```sh
npm ci
npx vsce package --pre-release
```