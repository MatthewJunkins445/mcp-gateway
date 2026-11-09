from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mcp_gateway.cli import main
from mcp_gateway.state import write_json


class ApprovalErrorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.candidate_path = self.state / "candidate.json"

    def approve(self):
        errors = StringIO()
        argv = ["mcp-gateway", "--state", str(self.state), "approve",
                "--tool", "demo/add", "--digest", "wrong-digest"]
        with patch("sys.argv", argv), redirect_stderr(errors):
            status = main()
        self.assertEqual(status, 1)
        self.assertFalse((self.state / "tools.lock.json").exists())
        return errors.getvalue()

    def test_digest_mismatch_explains_recovery_without_exposing_candidate(self):
        write_json(self.candidate_path, {"version": 1, "tools": {}, "private": "DO_NOT_EXPOSE"})
        before = self.candidate_path.read_bytes()
        error = self.approve()
        self.assertIn("Candidate changed; review its diff again", error)
        self.assertNotIn("DO_NOT_EXPOSE", error)
        self.assertEqual(self.candidate_path.read_bytes(), before)

    def test_missing_candidate_tells_operator_to_discover(self):
        self.assertIn("run discover first", self.approve())

    def test_unexpected_errors_still_use_generic_message(self):
        write_json(self.candidate_path, {"version": 1, "tools": {}})
        with patch("mcp_gateway.cli.read_json", side_effect=RuntimeError("DO_NOT_EXPOSE")):
            error = self.approve()
        self.assertIn("Check configuration, state integrity", error)
        self.assertNotIn("DO_NOT_EXPOSE", error)
