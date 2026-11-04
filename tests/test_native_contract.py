"""Static proof obligations for the native FM27 engine inspection stage."""

import ast
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fm_match_sim.cli import main
from fm_match_sim.native_contract import RESEARCH_EDGES, audit_native_contract
from fm_match_sim.pe import KNOWN_SHA256

ENTRY_RVAS = {
    "fixture_factory": "0xC33370",
    "match_builder": "0x351B2B0",
    "builder_args": "0x42CAE30",
    "prepare_candidate": "0x16B8DBD0",
    "prepare_setup": "0x4963300",
    "prepare_phase_ff": "0x4962E70",
    "prepare_phase_zero": "0x4962690",
    "ordinary_run_caller": "0xC30710",
    "play_to_end": "0x4520BD0",
    "match_reader": "0x4973930",
}


def report(with_edges=True):
    records = {}
    for name, rva in ENTRY_RVAS.items():
        records[name] = {
            "name": name,
            "requested_rva": rva,
            "exact_function_entry": True,
            "function": {
                "entry_rva": rva,
                "calling_convention": "__fastcall",
                "database_parameters": [{"name": "param_1"}],
            },
            "decompilation": {"status": "decompiled"},
            "incoming": [],
            "outgoing": [],
            "high_pcode_calls": [],
        }
    if with_edges:
        for src, dest, _ in RESEARCH_EDGES:
            records[src]["outgoing"].append({
                "target_function_rva": ENTRY_RVAS[dest],
                "target_rva": ENTRY_RVAS[dest],
                "callsite_rva": "0x123456",
            })
    records["ordinary_run_caller"]["high_pcode_calls"].append({
        "target_rva": ENTRY_RVAS["play_to_end"],
        "callsite_rva": "0xC31234",
        "argument_count": 3,
        "pcode_arguments": ["(register, 0x20, 8)", "(const, 0x1, 4)",
                            "(const, 0xffffffffffffffff, 8)"],
    })
    return {
        "schema_version": 1,
        "project_file": "game_plugin.dll",
        "expected_sha256": KNOWN_SHA256,
        "ghidra_executable_sha256": KNOWN_SHA256,
        "read_only": True,
        "native_code_executed": False,
        "functions": list(records.values()),
    }


class NativeContractTests(unittest.TestCase):
    def test_reports_all_research_edges_without_claiming_executability(self):
        audit = audit_native_contract(report())
        self.assertEqual(audit["direct_lifecycle_edges_observed"], len(RESEARCH_EDGES))
        self.assertFalse(audit["native_execution_ready"])
        self.assertEqual(audit["ordinary_caller_to_play_high_pcode"][0]["argument_count"], 3)
        self.assertEqual(audit["build_hash_verified"], True)
        self.assertTrue(audit["unresolved_blockers"])

    def test_missing_edges_are_not_false_success(self):
        audit = audit_native_contract(report(with_edges=False))
        self.assertEqual(audit["direct_lifecycle_edges_observed"], 0)
        self.assertFalse(audit["native_execution_ready"])

    def test_rejects_wrong_hash_or_executed_code(self):
        item = report()
        item["ghidra_executable_sha256"] = "bad"
        with self.assertRaisesRegex(ValueError, "hash"):
            audit_native_contract(item)
        item = report()
        item["native_code_executed"] = True
        with self.assertRaisesRegex(ValueError, "nonexecuting"):
            audit_native_contract(item)

    def test_offline_cli_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / "ghidra.json", Path(folder) / "audit.json"
            source.write_text(json.dumps(report()), encoding="utf-8")
            with patch("builtins.print"):
                status = main(["audit-native-contract", "--report", str(source),
                               "--out", str(target)])
            self.assertEqual(status, 0)
            output = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(output["direct_lifecycle_edges_observed"], len(RESEARCH_EDGES))

    def test_ghidra_script_is_valid_python_syntax_and_read_only(self):
        script = (Path(__file__).resolve().parents[1] /
                  "ghidra_scripts" / "Fm27MatchCallgraph.py")
        contents = script.read_text(encoding="utf-8")
        ast.parse(contents, filename=str(script))
        self.assertIn("getScriptArgs()", contents)
        self.assertIn("getExecutableSHA256()", contents)
        self.assertNotIn("WriteProcessMemory", contents)
        self.assertNotIn("CreateRemoteThread", contents)
        self.assertNotIn("setBytes(", contents)


if __name__ == "__main__":
    unittest.main()
