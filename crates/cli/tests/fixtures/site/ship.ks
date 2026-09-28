name:  api
on:    push main

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
    image: build.tag
    to:    apply.out.cluster
    wait:  healthy, 5m
