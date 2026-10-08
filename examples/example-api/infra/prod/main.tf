# infra/prod — the cluster example-api deploys to: a local kind cluster.
#
# `keepshipping check` reads this file's `output` blocks and types
# `apply.out.cluster` as `k8s.Cluster` — from the shape below, without
# running tofu and without reaching the registry.

terraform {
  required_providers {
    kind = {
      source  = "tehcyx/kind"
      version = "~> 0.11"
    }
  }
}

resource "kind_cluster" "example_api" {
  # Pinned, so `tofu plan` is the same plan on every laptop. Bump it
  # deliberately; an unpinned node image makes plans drift.
  node_image = "kindest/node:v1.31.0"

  name = "example-api"

  # The control plane is not up until it answers; without this, the rollout
  # would race a cluster that is still booting.
  wait_for_ready = true
}

# How to reach the cluster and how to authenticate — never a credential. The
# three keys are what `check` recognises as a cluster; the kubeconfig kind
# writes is executed, not pasted here.
output "cluster" {
  value = {
    endpoint = kind_cluster.example_api.endpoint
    ca       = kind_cluster.example_api.cluster_ca_certificate
    auth     = "exec"
  }
}