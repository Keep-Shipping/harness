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

## `tofu.plan` (v1.0.0)

Plans an infrastructure directory, and reports what it would change.

- Action: plan
- Requires: IacTool

Inputs:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `dir` | path | - | the directory to plan |
| `backend` | string | `local` | the backend kind |
| `backend_config` | map | {} | backend settings for `tofu init` |
| `vars` | map | {} | the input variables the plan is made with |

Outputs:

| Name | Type | Description |
| --- | --- | --- |
| `file` | map | the saved plan as `{ path, sha256 }` |
| `changes` | map | the plan's resources, and the three counts |
| `adds` | int | how many it creates, replacements included |
| `changes_count` | int | how many it updates in place |
| `destroys` | int | how many it destroys, replacements included |
| `empty` | bool | whether it changes nothing |
| `summary` | string | the plan in plain terms |
