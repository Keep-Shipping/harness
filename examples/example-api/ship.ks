keepshipping: 0.1

# example-api: image → cluster → rollout, with a human in the middle.
name:         example-api
on:           push main

steps:
  build:    oci.image
    from:   ./Dockerfile
    push:   ghcr.io/example/example-api:{git.sha}
    sign:   true

  plan:     tofu.plan
    dir:    ./infra/prod

  review:   approval
    show:   plan.changes
    from:   @platform

  apply:    tofu.apply
    plan:   plan.file        # the exact plan you approved

  deploy:   k8s.rollout
    image:  build.digest     # oci.Digest, never a tag
    to:     apply.out.cluster
    wait:   healthy, 5m

policy:
  agents:
    can:    build, plan
    before: apply
    ask:    @platform
