# Editors

A site file is named `ship.ks`, or `<something>.ship.ks`. Every package here
claims those two names and nothing else: `.ks` belongs to Red Hat/Fedora
Kickstart ([LANGUAGE.md, "File name and
association"](LANGUAGE.md#file-name-and-association)). The `editor_association`
test in `ks-testing` fails the build if a grammar starts claiming `ks`, `.ks`
or `*.ks`.

The extension and the setups below start `keepshipping lsp` over stdio; the
binary must be on `PATH`, though VS Code, Zed and LSP4IJ each also take an
explicit path to it.

## VS Code

`editors/vscode` is a pre-release extension under the `Keep-Shipping`
publisher; `keepshipping.server.path` overrides the binary (default
`keepshipping`). To build a `.vsix` locally:

```sh
cd editors/vscode
npm ci
npx vsce package --pre-release
```

## Tree-sitter grammar

`editors/tree-sitter-keepshipping` holds `grammar.js` and
`queries/highlights.scm`. It is a highlighting grammar, not an implementation
of [LANGUAGE.md](LANGUAGE.md#lexical-grammar): there is no external scanner, so
no INDENT/DEDENT tokens, and the body of a block string (`key: |`) is
tokenised as ordinary lines. What keeps it honest is that every shared fixture
must parse without one ERROR node — the `tree-sitter` job in
`.github/workflows/editors.yml` runs `tree-sitter generate` and parses
everything under `crates/*/tests/fixtures/**/*.ks`.

## Neovim

Neovim 0.11+, with nvim-treesitter:

```lua
vim.filetype.add {
  filename = { ['ship.ks'] = 'keepshipping' },
  pattern = { ['.*%.ship%.ks'] = 'keepshipping' },
}

local parsers = require('nvim-treesitter.parsers').get_parser_configs()
parsers.keepshipping = {
  install_info = {
    url = 'https://github.com/Keep-Shipping/harness',
    location = 'editors/tree-sitter-keepshipping',
    files = { 'src/parser.c' },
    requires_generate_from_grammar = true,
  },
}

vim.lsp.config('keepshipping', {
  cmd = { 'keepshipping', 'lsp' },
  filetypes = { 'keepshipping' },
  root_markers = { 'ship.ks', '.git' },
})
vim.lsp.enable('keepshipping')
```

Then `:TSInstall keepshipping`. The subdirectory key is `location`, and
`requires_generate_from_grammar` makes nvim-treesitter run `tree-sitter
generate` itself — which needs the tree-sitter CLI and Node on `PATH`. An
install copies no queries, so copy `queries/highlights.scm` to
`queries/keepshipping/highlights.scm` in your Neovim runtime.

`vim.filetype.add` patterns are anchored for you: nvim wraps each one as
`^…$` and matches it against the whole path
(`runtime/lua/vim/filetype.lua`, `M.add`/`M.match`), so `.*%.ship%.ks`
matches `api.ship.ks` and not `myship.ks`, and not a file that merely sits
inside a `*.ship.ks` directory. nvim-lspconfig users put the same `cmd` and
`filetypes` in `lsp/keepshipping.lua` instead of calling `vim.lsp.config`.

## Zed

A sketch for a dev extension, not a published one: Zed reaches no language
that is not behind an extension, so `zed: install dev extension` needs an
`extension.toml` of

```toml
id = "keepshipping"
name = "Keep Shipping"
version = "0.0.1"
schema_version = 1
languages = ["languages/keepshipping"]

[grammars.keepshipping]
repository = "https://github.com/Keep-Shipping/harness"
rev = "<commit-sha>"
path = "editors/tree-sitter-keepshipping"
```

plus a `languages/keepshipping/config.toml` of

```toml
name = "Keep Shipping"
grammar = "keepshipping"
path_suffixes = ["ship.ks"]
```

`path_suffixes` supports no globs, but it does not need one. Zed
(`crates/language/src/available_languages.rs`, `find_for_file`) takes three
candidates from a path — the last dot-separated segment, the whole file name
and the full path — and accepts a suffix when a candidate *equals* it or
*ends with a `.` followed by it*. So `ship.ks` matches `ship.ks` exactly and
`foo.ship.ks` through its `.ship.ks` tail, but not `myship.ks`, which only
ends with `ship.ks` and nothing dotted. A suffix carrying its own leading dot
never matches anything: the dot is doubled into `..ks`. Zed does have a glob
mechanism — the per-user `file_types` setting, which it compiles with
`globset` — but that is a settings change the extension cannot ship, so the
extension carries `path_suffixes` alone.

Zed also compiles an existing `src/parser.c` with clang and never runs
`tree-sitter generate`; since `src/` is not committed, the `rev` above has to
name a commit carrying the generated parser.

The server is declared with `[language_servers.keepshipping]`. The binary is a
user setting, and Zed wants an absolute path:

```json
{
  "languages": { "Keep Shipping": { "language_servers": ["keepshipping"] } },
  "lsp": { "keepshipping": { "binary": {
    "path": "/usr/local/bin/keepshipping", "arguments": ["lsp"] } } }
}
```

## JetBrains

With [LSP4IJ](https://plugins.jetbrains.com/plugin/23257-lsp4ij), under
**Settings | Languages & Frameworks | Language Servers**:

- `[+]` opens **New Language Server**; the *Server* tab wants a `Name:` and a
  `Command:` — `keepshipping lsp`, arguments inline in that one string.
- The *Mappings* tab has three separate tables. Use **File name patterns**,
  not a custom file type: `ship.ks;*.ship.ks` paired with **Language Id**
  `keepshipping`, which is what the server receives as
  `textDocument.languageId`. A custom file type turns off TextMate
  coloration.
- **Settings | Editor | TextMate Bundles | Add** takes a `.tmBundle` or a
  folder holding a VS Code `package.json`; point it at `editors/vscode` and
  the highlighting comes with it.