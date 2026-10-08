# deploy the api: image → infra → prod
name:  api
on:    push main

envs:
  staging:
    ci-only: true
  prod:
    ci-only: true

steps:
  build:   oci.image
    from:  ./Dockerfile
    push:  ghcr.io/acme/api:{git.sha}
    sign:  true

  plan:    tofu.plan
    dir:   ./infra/prod

  review:  approval
    show:  plan.changes
    from:  @platform

  apply:   tofu.apply
    plan:  plan.file        # the exact plan you approved

  deploy:  k8s.rollout
    image: build.digest     # oci.Digest, never a tag
    to:    apply.out.cluster
    wait:  healthy, 5m

policy:
  agents:
    can:    check, build, plan, deploy staging
    ask:    @platform
    before: apply, deploy prod, destroy
    never:  read secrets
# humans follow the same file, minus the leash