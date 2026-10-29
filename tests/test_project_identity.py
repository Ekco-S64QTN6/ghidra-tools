#!/usr/bin/env python3
"""Regression tests for collision-resistant Ghidra project identity."""

import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
import project_identity  # noqa: E402


class ProjectIdentityTests(unittest.TestCase):
    def test_same_basename_in_different_directories_gets_distinct_projects(self):
        with tempfile.TemporaryDirectory(prefix="project-identity-") as temp:
            first_dir = os.path.join(temp, "first")
            second_dir = os.path.join(temp, "second")
            os.makedirs(first_dir)
            os.makedirs(second_dir)
            first = os.path.join(first_dir, "sample.bin")
            second = os.path.join(second_dir, "sample.bin")
            with open(first, "wb") as handle:
                handle.write(b"identical payload")
            with open(second, "wb") as handle:
                handle.write(b"identical payload")

            first_name = project_identity.project_identity(first)
            second_name = project_identity.project_identity(second)
            first_output = project_identity.output_identity(first)
            second_output = project_identity.output_identity(second)
            self.assertNotEqual(first_name, second_name)
            self.assertNotEqual(first_output, second_output)
            self.assertIn("sample_bin", first_name)
            self.assertIn("sample_bin", second_name)

    def test_changed_content_at_same_path_gets_a_new_project(self):
        with tempfile.TemporaryDirectory(prefix="project-identity-") as temp:
            path = os.path.join(temp, "sample.bin")
            with open(path, "wb") as handle:
                handle.write(b"first sample")
            first_name = project_identity.project_identity(path)
            with open(path, "wb") as handle:
                handle.write(b"second sample")
            second_name = project_identity.project_identity(path)
            self.assertNotEqual(first_name, second_name)

    def test_output_identity_changes_when_file_content_changes(self):
        with tempfile.TemporaryDirectory(prefix="project-identity-") as temp:
            path = os.path.join(temp, "sample.bin")
            with open(path, "wb") as handle:
                handle.write(b"first output")
            first = project_identity.output_identity(path)
            with open(path, "wb") as handle:
                handle.write(b"second output")
            second = project_identity.output_identity(path)
            self.assertNotEqual(first, second)

    def test_project_settings_do_not_change_the_stable_output_identity(self):
        with tempfile.TemporaryDirectory(prefix="project-identity-") as temp:
            path = os.path.join(temp, "sample.bin")
            with open(path, "wb") as handle:
                handle.write(b"same source")
            self.assertEqual(
                project_identity.output_identity(path),
                project_identity.identities(path, "false", "/opt/ghidra")[1],
            )

    def test_identity_is_stable_for_same_path_content_and_settings(self):
        with tempfile.TemporaryDirectory(prefix="project-identity-") as temp:
            path = os.path.join(temp, "sample.bin")
            with open(path, "wb") as handle:
                handle.write(b"stable sample")
            first = project_identity.project_identity(path, "false", "/opt/ghidra")
            second = project_identity.project_identity(path, "false", "/opt/ghidra")
            self.assertEqual(first, second)

    def test_project_affecting_settings_change_the_identity(self):
        with tempfile.TemporaryDirectory(prefix="project-identity-") as temp:
            path = os.path.join(temp, "sample.bin")
            with open(path, "wb") as handle:
                handle.write(b"stable sample")
            baseline = project_identity.project_identity(path, "false", "/opt/ghidra")
            findcrypt = project_identity.project_identity(path, "true", "/opt/ghidra")
            other_ghidra = project_identity.project_identity(path, "false", "/usr/share/ghidra")
            self.assertNotEqual(baseline, findcrypt)
            self.assertNotEqual(baseline, other_ghidra)

    def test_name_is_safe_and_bounded_for_long_filenames(self):
        with tempfile.TemporaryDirectory(prefix="project-identity-") as temp:
            path = os.path.join(temp, "very long filename with spaces" * 6 + ".bin")
            with open(path, "wb") as handle:
                handle.write(b"payload")
            name = project_identity.project_identity(path)
            self.assertLessEqual(len(name), 110)
            self.assertRegex(name, r"^[a-zA-Z0-9_]+$")
            self.assertNotIn("/", name)
            self.assertNotIn(" ", name)

    def test_missing_files_fail_with_a_nonzero_cli_status(self):
        missing = os.path.join(tempfile.gettempdir(), "this-file-should-not-exist-project-identity.bin")
        try:
            os.remove(missing)
        except FileNotFoundError:
            pass
        result = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "project_identity.py"), missing],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not exist", result.stderr)

    def test_main_cli_uses_the_collision_resistant_identity(self):
        with tempfile.TemporaryDirectory(prefix="project-identity-") as temp:
            path = os.path.join(temp, "sample.bin")
            with open(path, "wb") as handle:
                handle.write(b"cli sample")
            result = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "scripts", "project_identity.py"), path, "false", ""],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.stdout.strip(), project_identity.project_identity(path, "false", ""))

        output_cli = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "project_identity.py"), "output", path],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(output_cli.stdout.strip(), project_identity.output_identity(path))

        identity_cli = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "project_identity.py"), "identities", path, "false", ""],
            check=True,
            capture_output=True,
            text=True,
        )
        project_name, output_key = identity_cli.stdout.rstrip("\n").split("\t")
        self.assertEqual(project_name, project_identity.project_identity(path, "false", ""))
        self.assertEqual(output_key, project_identity.output_identity(path))

        with open(os.path.join(REPO_ROOT, "ghidra-report.sh"), encoding="utf-8") as handle:
            shell = handle.read()
        self.assertIn('project_identity.py" identities', shell)
        self.assertIn('project_identity.py" output', shell)


if __name__ == "__main__":
    unittest.main(verbosity=2)
