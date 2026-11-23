# Dependencies and execution scope

The guard, static checker, scorecard and unit tests use Python's standard library.
The separate Living Map manifest job uses hash-locked PyYAML 6.0.2 from
`requirements-dev.txt` with the existing validator pinned at
`068ad51d476ae7090cd4abb8bf395be82e4b2f90`.
Direct `python3` execution installs nothing. `pyproject.toml` records the current
0.3.0 library version, the existing MIT licence and an optional setuptools build;
setuptools is a build dependency, not a runtime requirement. CI verifies Python
3.11 and 3.12 on Ubuntu 24.04. Package metadata retains the existing Python 3.9
compatibility claim; those older interpreters are not CI targets.

`jev_judge.py` uses standard-library HTTP to send selected document text to
TypeSafe at `https://api.typesafe.ai/v1/systemone`, using `JEV` or
`TYPESAFE_API_KEY` from the environment or a local `.env`. Its `uv run` metadata
requests Python 3.14; that can download an interpreter. It has no SDK dependency.
The default `jev-latest` identifier is mutable and is not a pinned model release.
No current model quality, region, pricing or processing terms are verified by CI.

The optional `demo/demo.py --live` imports the Anthropic SDK and makes two model
requests; SDK retries may add requests. The SDK is deliberately not installed by
the offline job. Select and test a controlled SDK/model revision, document the
provider's data handling, and approve a bounded budget before a live evaluation.
The existing live-demo default model is not validated by these checks.

Ordinary PR CI has no provider secrets and never starts Jev or `--live`. Model
assessment is a separate explicitly authorised operation. Empty/missing model
assessment is **not assessed**, never evidence of a passing evaluation.

Actions and the reusable checker are pinned to commit revisions. Review updates
and rerun the synthetic tests before changing pins. Hosted runner images and
Python patch releases still change; this is not a fully hermetic dependency lock.
