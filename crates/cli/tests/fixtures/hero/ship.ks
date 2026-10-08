# deploy the api: image → infra → prod
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

  migrate: ./ship/migrate.ts   # the escape hatch, next to this file
    db:    secret("db-url")

  deploy:  k8s.rollout
    after: migrate
    image: build.digest     # oci.Digest, never a tag
    to:    apply.out.cluster
    wait:  healthy, 5m
