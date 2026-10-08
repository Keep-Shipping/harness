# example-api

A small service, shipped the way the Keep Shipping harness wants it shipped:
the image is built from the Dockerfile here, the cluster comes out of OpenTofu,
a human approves the plan, and the rollout waits for the deployment to be
healthy.

- `ship.ks` — the workflow. Build, plan, review, apply, deploy.
- `app.py`, `Dockerfile` — the service: standard library only, so the image
  builds with nothing but the base image.
- `infra/prod/main.tf` — a local kind cluster, and the output that says how
  to reach it.

Read it in order, one step at a time, in the harness guide:
[GETTING_STARTED.md](../../docs/GETTING_STARTED.md).

To see what the file declares without running anything:

```sh
keepshipping check          # what it found, and nothing ran
keepshipping graph          # the plan: every step, in order, with what it waits on
keepshipping run --dry-run  # the same route, as a run would take it
```