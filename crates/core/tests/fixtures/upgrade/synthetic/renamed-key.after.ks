keepshipping: 0.2

# The pipeline the PR links to.
title:  deploy the api

on:    push main

steps:
  build:   oci.image
    from:  ./Dockerfile   # the image is built, never pasted
    push:  ghcr.io/acme/api:{git.sha}
    sign:  true

  notify: acme.chat
    name:  ops-room   # not the pipeline's name: a step input, left alone
    to:    deploy