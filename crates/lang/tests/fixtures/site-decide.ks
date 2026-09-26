  risk:    decide
    model:   typesafe/jev
    ask:     "How risky is this plan?"
    input:   plan.changes
    returns: low | medium | high

  review:  approval
    auto:    risk is low ≥ 0.95
             and plan.destroys == 0
    else:    ask @platform, show risk.reason
