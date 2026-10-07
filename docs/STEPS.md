<!--
Generated from the built-in step kinds; do not edit by hand.
Regenerate with: KS_BLESS=1 cargo test -p ks-engine --test steps_doc
-->

# Built-in steps

Every step kind the harness ships, with its declared schema. Inputs are
checked against the schema before the step runs; outputs, after.


## `oci.verify` (v1.0.0)

Refuses to continue unless an image digest carries a signature from a named identity.

- Action: other
- Requires: Registry, Signer

Inputs:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `image` | string | - | the digest-pinned image to verify, as `repository@sha256:…` |
| `signed_by` | string | - | who must have signed it: `key:<key-id>`, or `<subject> from <issuer>` |

Outputs:

| Name | Type | Description |
| --- | --- | --- |
| `digest` | string | the verified digest |
| `identity` | string | the identity the signature was made as |

## `tofu.apply` (v1.0.0)

Applies exactly the plan file an approval was bound to, refusing if its sha256 no longer matches.

- Action: apply
- Requires: IacTool

Inputs:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `plan` | map | - | the `tofu.PlanFile` `tofu.plan` emitted as `file`: `{path, sha256, dir}`, with `sha256` the digest the approval was bound to |

Outputs:

| Name | Type | Description |
| --- | --- | --- |
| `out` | map | the root module's non-sensitive outputs, by name; sensitive ones are counted in the log, never returned |
| `applied` | number | how many resources the apply changed (created, updated and destroyed) |
