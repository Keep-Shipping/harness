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
