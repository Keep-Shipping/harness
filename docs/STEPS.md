<!--
Generated from the built-in step kinds; do not edit by hand.
Regenerate with: KS_BLESS=1 cargo test -p ks-engine --test steps_doc
-->

# Built-in steps

Every step kind the harness ships, with its declared schema. Inputs are
checked against the schema before the step runs; outputs, after.


## `k8s.rollout` (v1.1.0)

Applies manifests to a cluster with every image pinned by digest, and waits for the workloads to become healthy.

- Action: deploy
- Requires: Cluster
- Optional: Registry, Signer

Inputs:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `to` | string | - | the cluster to deploy to: the environment's name |
| `manifests` | path | - | a manifest file or a directory |
| `image` | string | `` | one `repository@sha256:…` for every container running that repository |
| `images` | map | {} | digest-pinned images by container name, for a manifest with several images |
| `namespace` | string | `` | the namespace to deploy into |
| `wait` | list | [`healthy`, `5m`] | the state to wait for and how long, as `healthy, 5m` |
| `rollback` | string | `auto` | `auto` to roll back a rollout that does not settle, `none` to leave it |
| `verify` | string | `` | the identity every image above must be signed by, as `signed-by <identity>`: `signed-by key:release-key`, or `signed-by https://token.actions.githubusercontent.com from https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main`. An empty value verifies nothing |

Outputs:

| Name | Type | Description |
| --- | --- | --- |

## `oci.artifact` (v1.0.0)

Push files as an OCI artifact with an artifactType and media types.

- Action: build
- Requires: Registry
- Optional: Signer

Inputs:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `files` | list | - | the files to package as artifact layers |
| `type` | string | - | artifact type: `helm`, `spdx`, `cyclonedx`, or a verbatim media type |
| `push` | oci.Tag | - | where to push, e.g. `registry.example/charts/app:1.0.0` |
| `subject` | oci.Digest | `` | the image digest this artifact describes, if any (empty for none) |
| `sign` | bool | false | sign the pushed manifest digest |

Outputs:

| Name | Type | Description |
| --- | --- | --- |
| `digest` | oci.Digest | the manifest digest the registry reported |
| `ref` | oci.Ref | the repository@digest reference (by digest, never a tag) |

## `oci.image` (v1.0.0)

Builds a container image from a Dockerfile, pushes it, and reports the digest the registry confirms.

- Action: build
- Requires: ImageBuilder, Registry
- Optional: Signer

Inputs:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `from` | path | - | the Dockerfile to build |
| `context` | path | - | the build context directory; defaults to the Dockerfile's own directory |
| `args` | map | {} | build args, as ARGs |
| `secrets` | map | {} | secret values by mount name, mounted into the build and never passed as args |
| `platforms` | list | [] | platforms to build for; more than one produces an image index. Empty means the platform the build runs on |
| `target` | string | `` | the stage to build |
| `push` | oci.Tag | - | the image reference to push |
| `sign` | bool | false | whether to sign the image |
| `sbom` | bool | false | whether to ask for an SBOM alongside the image |
| `cache` | string | `local` | where the builder may keep its cache: `registry`, `local` or `none` |

Outputs:

| Name | Type | Description |
| --- | --- | --- |
| `digest` | oci.Digest | the digest the registry holds |
| `ref` | oci.Ref | the image pinned to that digest, as `<repository>@<digest>` |
| `tag` | oci.Tag | the reference that was pushed |
| `signed` | bool | whether it was signed |
| `sbom` | oci.Artifact | the SBOM artifact's digest, or empty when there is none |
| `platforms` | list | the platforms the image was built for |

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

## `vm.deploy` (v1.1.0)

Deploys to a fleet of hosts over SSH, one batch at a time, and reports how many came up.

- Action: deploy
- Requires: RemoteShell
- Optional: Registry, Signer

Inputs:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `hosts` | list | - | the fleet: `address` and `host_key` are required on every entry, and a host with no pinned `host_key` is refused rather than trusted on first use. Each entry also takes `port` (22), `user` (`ssh_user`), and `host_key_algorithm` (`ssh-ed25519`) |
| `batch` | string | `1` | how many hosts per batch: a count, or a percent of the fleet such as `"25%"`. A percent rounds up and is never zero |
| `run` | list | - | commands to run on each host as it is deployed, in order, as `{ program, args, timeout }`. The argv is typed, never a shell string |
| `health` | string | - | a probe command to run on each host after its commands; the deploy waits for it to report healthy. Without one there is no health gate |
| `health_timeout` | int | 60 | how long the health gate polls a host before calling it failed |
| `max_failures` | int | 0 | how many hosts may fail health before the deploy stops and rolls back |
| `rollback` | list | - | commands that restore a host's previous artifact, in the same `{ program, args, timeout }` shape as `run`, run on every host of a failed batch |
| `ssh_user` | string | `deploy` | the user to deploy as, for the hosts that do not name one |
| `image` | string | - | the digest-pinned artifact the deploy ships, as `repository@sha256:…`; verification checks the signature on this digest |
| `verify` | string | `` | the identity `image` must be signed by, as `signed-by <identity>`: `signed-by key:release-key`, or `signed-by https://token.actions.githubusercontent.com from https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main`. An empty value verifies nothing |

Outputs:

| Name | Type | Description |
| --- | --- | --- |
| `healthy` | int | the hosts that reached health |
| `total` | int | the hosts in the fleet |
| `summary` | string | the fleet in one line, as `{healthy}/{total} hosts healthy` |
