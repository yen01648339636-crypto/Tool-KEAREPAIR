# Container command fixtures

These four small command records exercise the framework's source-attestation
contract without shipping benchmark source code, training datasets, or indices.

- `baseline_suite.json` retains a baseline comparison that installs the candidate
  into one checkout and tests a separate source copy.
- `javascript_suite.json`, `python_suite.json`, and `go_suite.json` retain
  representative independent PoC/Unit commands and their preparation steps.

`tests/test_container_validation.py` checks Bash syntax and explicit
`apply`/`before`/`after` boundaries for every command. The baseline test runs with
local checkout/build doubles; it checks both the baseline and candidate bytes,
source restoration, and the recorded source paths. The tests do not run benchmark
images or require the removed `data/processed` directories.

These are regression fixtures, not a runnable benchmark distribution. Supply
complete case sources, image references, and validation commands separately for
real repair experiments.
