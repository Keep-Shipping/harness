name: api
on:   push main

steps:
  build: oci.image
    from: ./Dockerfile
    push: ghcr.io/acme/api:{git.sha}
