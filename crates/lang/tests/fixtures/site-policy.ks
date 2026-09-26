policy:
  agents:
    can:    check, build, plan, deploy staging
    ask:    @platform
    before: apply, deploy prod, destroy
    never:  read secrets
# humans follow the same file, minus the leash
