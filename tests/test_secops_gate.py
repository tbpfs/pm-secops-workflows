#!/usr/bin/env python3
"""Unit tests for pm_secops_gate.py."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import pm_secops_gate  # noqa: E402


class TestSecOpsGate(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="test_secops_"))
        subprocess.run(["git", "init", "-q"], cwd=self.tmpdir, check=True)
        subprocess.run(["git", "config", "user.email", "ci@example.com"], cwd=self.tmpdir, check=True)
        subprocess.run(["git", "config", "user.name", "CI"], cwd=self.tmpdir, check=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_catches_secrets_unpinned_actions_and_passes_clean_repo(self) -> None:
        wf_dir = self.tmpdir / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "bad.yml").write_text(
            "name: Bad\non: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
            encoding="utf-8",
        )
        (self.tmpdir / "app.py").write_text("TOK = 'ghp_" + "A" * 36 + "'\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.tmpdir, check=True)

        errs = pm_secops_gate.scan_repository(self.tmpdir)
        self.assertTrue(any("機密外洩攔截" in e for e in errs))
        self.assertTrue(any("permissions:" in e for e in errs))
        self.assertTrue(any("40 字元 Commit SHA" in e for e in errs))

        # Fix issues -> clean pass
        (wf_dir / "bad.yml").write_text(
            "name: Good\non: push\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n",
            encoding="utf-8",
        )
        (self.tmpdir / "app.py").write_text("print('clean')\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.tmpdir, check=True)
        self.assertEqual(pm_secops_gate.scan_repository(self.tmpdir), [])

    def test_reusable_secops_efficiency_and_supply_chain_contract(self) -> None:
        wf_path = REPO_ROOT / ".github" / "workflows" / "reusable-secops.yml"
        txt = wf_path.read_text(encoding="utf-8")
        self.assertIn("install_ffmpeg:", txt)
        self.assertIn('INSTALL_FFMPEG: ${{ inputs.install_ffmpeg', txt)
        self.assertIn('if [[ "${INSTALL_FFMPEG}" == "1" ]]', txt)
        self.assertIn("actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9", txt)
        self.assertIn("cache: true", txt)
        self.assertIn("persist-credentials: false", txt)
        self.assertEqual(
            pm_secops_gate.scan_repository(REPO_ROOT, is_public_repo=True),
            [],
        )


if __name__ == "__main__":
    unittest.main()
