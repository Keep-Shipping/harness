# Stale plans: apply stops and asks again

An approved infrastructure plan is applied exactly as approved, or the run stops and asks again. This page says exactly which kinds of change are caught, and — as important — which are not.

The behaviour lives in `ks_engine::plan_guard`. The tool's own contract is in [`crates/core/src/ports/iac.rs`](../crates/core/src/ports/iac.rs): `apply` takes *only* a saved plan, re-hashes it, and refuses it with `IacError::StalePlan` if the state moved after the plan was written.

## What the guard does

1. **Optionally recheck.** With `recheck` on, a fresh plan is taken first and compared with the approved change set. If it differs, the run stops *before* `apply` records `plan.stale` with `cause: drift` and asks again. If it does not, the fresh plan is discarded and the run carries on.
2. **Apply the approved plan** — exactly the file the approval is bound to.
3. **On `IacError::StalePlan` from the tool** — the state moved — the run stops. It records `plan.stale` with `cause: state` *first*, then plans again and asks for a new approval. It never applies the new plan under the old approval.
4. **If that re-plan fails**, the stop is already on the record (with `replanned: null`) and the tool's error propagates. A run that stopped without saying why is worse than a run that stopped.
5. **On `recheck` with no difference**, the *approved* plan is applied and the fresh one is discarded. A plan nobody approved never reaches `apply`.

Why a `StalePlan` asks again even when the re-plan says the same thing: an approval is bound to a plan's sha256 (`ks_core::ports::approval`), and the comparison below cannot see attribute values. A new plan file contains things nobody reviewed, so it is asked about again regardless. The event still reports `differs: false`, so an approver who sees "same change set, new file" knows exactly what they are being asked about.

## What "differs" means

`plan_guard::diff(approved, fresh)` normalises each [`PlanJson`] to `address → [actions]` and drops any entry whose actions are exactly `[NoOp]` — an untouched resource is not a change. Two change sets **differ** iff:

- an address is in one and not the other (`added` / `removed`), or
- the same address has a different action list (`changed`, with `before` and `after`).

Order is significant: `[Delete, Create]` (replace) and `[Create, Delete]` (create-before-destroy) are different plans. `Read` counts as an action like any other, so a new data source being read is a difference. A duplicate address keeps its first entry.

**Attribute values are not compared.** `PlanJson` carries addresses and actions, not values. A resource that drifted in an attribute the plan *already* updates, with the same action, compares equal.

## What is caught

| What changed between the plan and the apply | `recheck` off | `recheck` on |
| --- | --- | --- |
| **State moved since the plan was written** (another apply, another writer to the backend). The tool refuses the saved plan. | Caught. Stops, re-plans, asks again, `cause: state`. | Caught, the same way — the recheck does not weaken it. |
| **Out-of-band drift that changes the change set**: a console edit made a resource already in the plan need replacing, or a new resource appeared. The state serial did not move, so the tool's check passes. | **Not caught.** The approved plan applies. | Caught. Stops before `apply`, asks again, `cause: drift`. |
| **Out-of-band drift that only moves attribute values of a resource the plan already touches with the same action.** | Not caught. | **Not caught** — values are invisible to the comparison. |
| **Drift covered by `ignore_changes` (or otherwise producing no planned change).** | Not caught, and arguably irrelevant: it changes no plan. | Not caught, same reasoning. |
| **Something changes after the recheck's fresh plan and before `apply`.** | The tool's own state check still applies: a state move is caught. Drift in that window is not. | Same: caught for state, not for drift. The recheck narrows the window; it does not close it. |

The last row is the honest limit: `recheck` compares two plans taken milliseconds apart. Between the second plan and the apply, somebody can still move the world without moving the state serial.

## The `recheck` default

- **On** for an environment declared `ci-only: true` — where a stop costs a re-run rather than a human's time.
- **Off** everywhere else.
- An explicit `recheck:` value in the workflow always wins, in either direction.

Resolved by `plan_guard::resolve_recheck(explicit, env)`, with the environment default from `plan_guard::recheck_default(env)`.

## The `plan.stale` run-log event

Emitted once per stop, before the run parks at the approval again. It fails closed: if the run log will not take the entry, the guard applies nothing and reports an error.

| Field | Meaning |
| --- | --- |
| `step` | The step that was applying. |
| `cause` | `"state"` (the tool found the state moved) or `"drift"` (a recheck found the change set differs). |
| `approved` | The sha256 of the plan the existing approval is bound to. |
| `replanned` | The sha256 of the fresh plan now in front of approvers, or `null` when the re-plan failed and there is no new plan to ask about. |
| `differs` | Whether the fresh plan's change set differs from the approved one's, or `null` when there is no fresh plan to compare. Informational either way — a fresh plan is asked about again regardless. |

Digests, not plan contents: the port keeps raw plan values out of the log.

`replanned` and `differs` are `null` on exactly one path: the tool reported the state moved, and the guard's own re-plan then failed. The stop is still recorded — that is why the event is written *before* the re-plan, not after — so a run whose re-plan broke is still readable afterwards. In the JSONL log they are written as JSON `null`, never as dropped keys, so a reader can tell "the re-plan failed" from "this build does not know the field".

## Site wording

The sentence on the site reads:

> If the world changed since the plan, apply stops and asks again.
> ([Keep-Shipping/website#5](https://github.com/Keep-Shipping/website/issues/5))

Checked against the table above:

- **"The world changed" — the state-moved case: true, always.** The tool refuses the saved plan, and the run stops and asks again, with or without `recheck`.
- **"The world changed" — out-of-band drift: true only with `recheck` on, and only when the change set differs.** With `recheck` off, or when the drift does not change the change set (attribute values under an action the plan already takes, or anything under `ignore_changes`), the approved plan applies without a stop.

So as written the sentence promises more than the guard delivers: a reader will take "the world changed" to include a teammate's console edit, and that case is exactly the one `recheck` exists to catch — and it is off by default outside `ci-only` environments.

A wording that matches:

> If the state changed since the plan, apply stops and asks again. With `recheck` on, a change in what the plan would do — not just the state — stops it too.

Or, in one sentence for a reader who does not want the detail:

> If the state changed since the plan, or — with `recheck` — what the plan would do changed, apply stops and asks again. Changes the plan does not mention are not caught.