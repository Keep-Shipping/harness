# a TypeScript step, and a ks step that reads what it declares
name:  api
on:    push main

steps:
  migrate: ./ship/migrate.ts

  build:   oci.image
    from:   ./Dockerfile
    push:   ghcr.io/acme/api:v{migrate.applied}