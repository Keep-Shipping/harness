name: api
steps:
  review: approval
  apply:  tofu.apply
policy:
  agents:
    before: apply
