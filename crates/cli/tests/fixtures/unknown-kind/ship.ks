# a kind the catalog does not know: KS0603 warns, and the check still passes
steps:
  plan: tofu.plna
    dir: ./infra

  notify: madeup.kind
    room: ops
