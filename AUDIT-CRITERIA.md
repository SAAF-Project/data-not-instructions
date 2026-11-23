# Data, Not Instructions: proposed verification criteria

These repository-specific criteria support the existing SAAF standards; they do
not establish a new organisation norm. Run `python3 -m unittest discover -s tests
-v`, `python3 demo/demo.py`, `python3 check_prompts.py demo` and `python3
scorecard.py` at the reviewed commit. Record the commit and actual CI outcome.
A missing/skipped test or provider evaluation remains **not assessed**.

| ID | Criterion | Executable evidence |
|---|---|---|
| DNI-01 [code] | Every default guard call gets a fresh nonce; planted closing tags and source attributes cannot break the tested wrapper. | `GuardTests.test_nonce_is_random_per_call`, `test_fake_closing_tag_is_neutralised`, `test_source_attribute_cannot_break_tag` |
| DNI-02 [code] | Invisible characters are removed and detected; warnings remain visible on the synthetic poisoned example. | `GuardTests.test_invisible_characters_removed_and_hidden_phrase_detected`, `test_poisoned_demo_report_is_flagged` |
| DNI-03 [code] | Recognised raw document interpolation fails while guarded fixture code passes. | `CheckPromptsTests.test_flags_unguarded`, `test_passes_guarded`, `test_inline_guard_call_passes` |
| DNI-04 [code] | Missing, empty, unreadable, invalid UTF-8/Python and symlink scan scopes are not successful checks. | `ScanFailureTests` in `tests/test_fail_closed.py` |
| DNI-05 [code] | Caller paths remain inside their checkout; caller modules cannot shadow the trusted checker. | `ScanFailureTests.test_workflow_blocks_parent_absolute_empty_and_symlink_escape`, `test_workflow_does_not_import_caller_module` |
| DNI-06 [code] | Missing/non-finite/out-of-range model probabilities cannot become clean; existing thresholds are preserved. | `JudgeValidationTests` (mocked provider responses only) |
| DNI-07 [code] | Existing synthetic corpus regressions fail without hiding known misses and false alarms. | `FixtureCorpusTests.test_all_fixtures`, `scorecard.py`, `tests/known_gaps.json` |
| DNI-08 [llm] | A selected model resists representative injection attempts without unacceptable false alarms under agreed acceptance thresholds. | **Not assessed** by this PR/CI. Requires versioned provider/model, dataset, data permission, cost limit and actual results. |

At the initial reviewed corpus, 95/212 cases match expectation: 86/188 attacks
flagged and 9/24 benign examples clean (102 missed attacks, 15 false alarms).
Passing regression tests means no unrecorded change against that baseline; it
does not mean all attacks were detected. These are synthetic warning-layer tests,
not proof of downstream model behaviour or audit quality.

The original MIT licence and team credits remain intact. `confirmed: false` in
`agent.yaml` records unconfirmed catalog metadata; it does not assign an
operational owner. Owner acceptance and a private security contact remain open.
