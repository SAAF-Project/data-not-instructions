"""Synthetic source and mocked provider answers only; no live requests."""
import io
import json
import math
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_prompts
import jev_judge
import run_check


class ScanFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def cli(self, *paths):
        return subprocess.run([sys.executable, check_prompts.__file__, *map(str, paths)], capture_output=True, text=True)

    def test_missing_and_empty_scope_are_not_assessed(self):
        for path in [self.root, self.root / 'missing']:
            result = self.cli(path)
            self.assertEqual(result.returncode, 2)
            self.assertIn('NOT ASSESSED', result.stderr)

    def test_invalid_python_fails_even_without_recognised_llm_call(self):
        source = self.root / 'agent.py'
        source.write_text('def broken(')
        self.assertEqual(self.cli(source).returncode, 2)

    def test_unreadable_or_invalid_utf8_is_not_ignored(self):
        source = self.root / 'agent.py'
        source.write_bytes(b'\xff')
        self.assertEqual(self.cli(source).returncode, 2)
        with mock.patch.object(pathlib.Path, 'read_text', side_effect=PermissionError):
            with self.assertRaises(check_prompts.ScanError):
                check_prompts.check_file(source)

    def test_mixed_targets_preserve_incomplete_outcome(self):
        source = self.root / 'agent.py'
        source.write_text('pass')
        self.assertEqual(self.cli(source, self.root / 'missing').returncode, 2)

    def test_symlink_source_is_not_followed(self):
        source = self.root / 'agent.py'
        source.write_text('pass')
        link = self.root / 'link.py'
        link.symlink_to(source)
        self.assertEqual(self.cli(link).returncode, 2)

    def test_valid_non_llm_source_is_completed(self):
        source = self.root / 'agent.py'
        source.write_text('pass')
        self.assertEqual(self.cli(source).returncode, 0)

    def test_workflow_blocks_parent_absolute_empty_and_symlink_escape(self):
        (self.root / 'escape').symlink_to(self.root.parent, target_is_directory=True)
        for path in ['..', str(self.root), '', 'escape']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                run_check.targets(self.root, path)

    def test_workflow_does_not_import_caller_module(self):
        (self.root / 'ast.py').write_text('raise RuntimeError("untrusted caller code executed")')
        (self.root / 'agent.py').write_text('c.messages.create(content=f"Review {policy_text}")')
        result = subprocess.run([sys.executable, '-I', run_check.__file__, str(self.root), '.'],
                                cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn('RuntimeError:', result.stderr)

    def test_workflow_does_not_resolve_internal_symlinks_into_passes(self):
        folder = self.root / 'source'
        folder.mkdir()
        (folder / 'agent.py').write_text('pass')
        (self.root / 'link.py').symlink_to(folder / 'agent.py')
        (self.root / 'linked-folder').symlink_to(folder, target_is_directory=True)
        for target in ['link.py', 'linked-folder/agent.py']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                run_check.targets(self.root, target)
            result = subprocess.run([sys.executable, '-I', run_check.__file__, str(self.root), target], capture_output=True)
            self.assertEqual(result.returncode, 2)


class JudgeValidationTests(unittest.TestCase):
    def clean(self):
        return {key: 0.0 for key in jev_judge.QUESTIONS}

    def test_non_finite_out_of_range_and_boolean_probabilities_fail(self):
        for value in [math.nan, math.inf, -math.inf, -0.1, 1.1, True, '0.5']:
            probabilities = self.clean()
            probabilities['override'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                jev_judge.decide(probabilities)

    def test_missing_probability_cannot_be_clean(self):
        probabilities = self.clean()
        del probabilities['override']
        with self.assertRaises(ValueError):
            jev_judge.decide(probabilities)

    def test_existing_threshold_states_are_preserved(self):
        probabilities = self.clean()
        self.assertEqual(jev_judge.decide(probabilities), jev_judge.Verdict.CLEAN)
        probabilities['override'] = 0.3
        self.assertEqual(jev_judge.decide(probabilities), jev_judge.Verdict.REVIEW)
        probabilities['override'] = 0.8
        self.assertEqual(jev_judge.decide(probabilities), jev_judge.Verdict.INJECTION)

    def test_invalid_mocked_provider_response_is_not_clean(self):
        answers = {key: {'noul': 0.0} for key in jev_judge.QUESTIONS}
        for invalid in [float('nan'), True]:
            answers['override']['noul'] = invalid
            response = io.BytesIO(json.dumps({'answers': answers}).encode())
            with mock.patch.object(jev_judge.urllib.request, 'urlopen', return_value=response) as request:
                with self.assertRaises(ValueError):
                    jev_judge.judge('synthetic evidence', key='synthetic-test-key')
                request.assert_called_once()

    def test_empty_input_does_not_request_provider(self):
        with mock.patch.object(jev_judge, 'judge') as judge:
            self.assertEqual(jev_judge.main([]), 2)
            with self.assertRaises(ValueError):
                jev_judge._evaluate([])
            judge.assert_not_called()
