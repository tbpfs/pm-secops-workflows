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
        # Phase 2B Stage 3b Fail-Closed & positive-allowlist contracts
        for needle in (
            "docker_run_env:",
            "docker_probe_path:",
            "docker_sensitive_paths:",
            "ENV_ITEM_RE='^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_./:@+-]*$'",
            "trap 'docker rm -f secops-probe",
            "State.Running",
            "^5[0-9]{2}$",
            "library CRITICAL",
        ):
            self.assertIn(needle, txt, f"Missing expected contract in reusable-secops.yml: {needle}")

        # Verify extracted bash scripts in reusable-secops.yml pass `bash -n` when bash is available
        bash_bin = shutil.which("bash")
        if bash_bin:
            import textwrap
            blocks: list[str] = []
            lines = txt.splitlines()
            i = 0
            while i < len(lines):
                if lines[i].lstrip().startswith("run: |"):
                    base_indent = len(lines[i]) - len(lines[i].lstrip(" "))
                    buf: list[str] = []
                    i += 1
                    while i < len(lines):
                        ln = lines[i]
                        if ln.strip() and (len(ln) - len(ln.lstrip(" "))) <= base_indent:
                            break
                        buf.append(ln)
                        i += 1
                    blocks.append(textwrap.dedent("\n".join(buf)))
                else:
                    i += 1
            self.assertGreaterEqual(len(blocks), 5)
            for idx, blk in enumerate(blocks):
                proc = subprocess.run([bash_bin, "-n"], input=blk, text=True, capture_output=True)
                self.assertEqual(proc.returncode, 0, f"bash -n failed on block #{idx}: {proc.stderr}")

    def test_cloudflare_key_secret_and_run_expression_injection_boundaries(self) -> None:
        wf_dir = self.tmpdir / ".github" / "workflows"
        wf_dir.mkdir(parents=True)

        # 1. Safe workflow: `- run: |` with sibling `env:` and `if:` using inputs.* -> 0 errors
        safe_wf = (
            "name: Safe\n"
            "on: workflow_dispatch\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  ok:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          echo \"${SAFE_VAR}\"\n"
            "        if: ${{ inputs.deploy_live == 'true' }}\n"
            "        env:\n"
            "          SAFE_VAR: ${{ inputs.user_note }}\n"
            "      - run: echo ok\n"
            "        env:\n"
            "          OTHER: ${{ github.event.issue.title }}\n"
        )
        (wf_dir / "safe.yml").write_text(safe_wf, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.tmpdir, check=True)
        self.assertEqual(pm_secops_gate.scan_repository(self.tmpdir), [])

        # 2. Unsafe patterns: |2 block, comment inside run:, newline plain scalar, multiline quote + wrapper, cfk_ secret
        unsafe_cases = [
            (
                "block_indent_num.yml",
                "name: U1\non: pull_request\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |2\n          echo ${{ github.head_ref }}\n",
            ),
            (
                "comment_in_run.yml",
                "name: U2\non: workflow_dispatch\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |-\n          # debug ${{ inputs.cmd }}\n          echo hi\n",
            ),
            (
                "newline_plain.yml",
                "name: U3\non: issues\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run:\n          echo ${{ github.event.issue.title }}\n",
            ),
            (
                "multiline_quoted_wrapper.yml",
                "name: U4\non: workflow_dispatch\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: \"echo\n          ${{ format('{0}', inputs.cmd) }}\"\n",
            ),
        ]
        for fname, content in unsafe_cases:
            (wf_dir / fname).write_text(content, encoding="utf-8")
            errs = pm_secops_gate.audit_workflows(self.tmpdir)
            self.assertTrue(
                any(fname in e and "Workflow 注入風險" in e for e in errs),
                f"Expected injection error for {fname}, got: {errs}",
            )
            (wf_dir / fname).unlink()

        # 3. cfk_ secret token detection (dynamically constructed to avoid self-trigger)
        (self.tmpdir / "leak.py").write_text("KEY = 'cfk_" + "Z" * 24 + "'\n", encoding="utf-8")
        subprocess.run(["git", "add", "leak.py"], cwd=self.tmpdir, check=True)
        errs_cfk = pm_secops_gate.scan_repository(self.tmpdir)
        self.assertTrue(any("機密外洩攔截" in e and "leak.py" in e for e in errs_cfk))


if __name__ == "__main__":
    unittest.main()
