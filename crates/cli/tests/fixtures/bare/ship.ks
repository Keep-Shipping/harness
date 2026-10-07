# no `on:`: the plan is the steps, with no event leading them
name: solo

steps:
  build:   oci.image
    from:  ./Dockerfile

  deploy:  k8s.rollout
    image: build.digest