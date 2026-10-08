# Test fixtures

Response bodies TypeSafe's Jev API is documented to return, transcribed from
`docs.typesafe.ai/api` (`/models`, the `POST /v1/systemone` section) on
2026-10-08 — checked by hand, **not** recorded against a live key: the account
that would own one is not available here, and a fixture that claimed to be a
capture would be a lie about its provenance.

Replace these with real captures: run the smoke workflow
(`.github/workflows/jev-smoke.yml`, `KS_JEV_SMOKE_KEY` set) with the response
body written to stdout, and diff what came back against these files. A vendor
response that drifts from these is a change in the API, and the adapter's
parsing is what should move.