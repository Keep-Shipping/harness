# the api's cluster: how to reach it, and how to authenticate — never a
# credential. `check` reads this shape and types `apply.out.cluster` as
# `k8s.Cluster` without running tofu.
output "cluster" {
  value = {
    endpoint = aws_eks_cluster.api.endpoint
    ca       = aws_eks_cluster.api.certificate_authority[0].data
    auth     = "eks"
  }
}

# keepshipping:type string
output "region" {
  value = aws_region.current.name
}