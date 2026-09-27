# acme/blocks · web-service@v3
block:  web-service
inputs:
  image:    oci.Digest
  domain:   string
  replicas: int = 2

# in any repo
  deploy:   acme/web-service@v3
    image:  build.digest
    domain: api.acme.dev
