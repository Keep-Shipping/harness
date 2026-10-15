# ADR 0016: MIT licence

Status: accepted, 2026-10-15. Supersedes the licence choice in
[ADR 0006](0006-licence-and-open-source-model.md).

## Context
[ADR 0006](0006-licence-and-open-source-model.md) chose open core with a
permissive licence and picked Apache-2.0 over MIT for its explicit patent
grant. The repository goes public on 2026-10-15, and the owner decided on MIT
instead: it is the licence of the Cratefield harness Keep Shipping is built
on, it is the shortest licence a security or legal reviewer can read, and it
matches the other Factory Zero open-source repositories.

## Decision
- **MIT for everything in this repository.** Everything else in ADR 0006
  stands: open core, the hosted control plane and team-only features in
  private repositories, Terraform/OpenTofu never bundled, fork risk accepted.
- Copyright is Factory Zero Pte. Ltd. Contributions come in under MIT
  (inbound is outbound); there is no CLA and no DCO.

## Consequences
- We give up Apache-2.0's express patent grant and its patent-retaliation
  clause. Users still get MIT's broad permission; the trade is accepted for
  simplicity and consistency with Cratefield.
- [LICENSE](../../LICENSE) and `editors/vscode/LICENSE` carry the MIT text;
  `license = "MIT"` in [Cargo.toml](../../Cargo.toml) and
  [fuzz/Cargo.toml](../../fuzz/Cargo.toml), `"license": "MIT"` in the TS SDK,
  the VS Code extension and the tree-sitter grammar.
- `cargo deny check licenses` keeps checking our own crates; MIT is already
  on the allowlist.
- Release archives ship the MIT LICENSE next to the binary.
