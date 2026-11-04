"""Conservative offline gate report for the FM27 Ghidra callgraph export.

This module does not interpret arbitrary function pointers as a safe ABI.
Passing structural gates does NOT mean native execution is available.
"""

from __future__ import annotations

from .pe import KNOWN_SHA256

# Direct calls already described in the user's native research report.
# Missing references in Ghidra are "not observed", not proof of absence.
RESEARCH_EDGES = (
    ("fixture_factory", "match_builder", "fixture build -> builder"),
    ("match_builder", "builder_args", "builder -> fixture args"),
    ("prepare_candidate", "prepare_setup", "ready -> setup"),
    ("prepare_candidate", "prepare_phase_ff", "ready -> phase 0xFF"),
    ("prepare_candidate", "prepare_phase_zero", "ready -> phase 0"),
    ("ordinary_run_caller", "play_to_end", "ordinary no-recording -> run"),
)


def _validate(report: dict) -> dict:
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("expected Ghidra native-callgraph schema version 1")
    if report.get("read_only") is not True or report.get("native_code_executed") is not False:
        raise ValueError("expected read-only, nonexecuting Ghidra report")
    if report.get("expected_sha256") != KNOWN_SHA256:
        raise ValueError("research DLL identity does not match the inspected build")
    actual = report.get("ghidra_executable_sha256")
    if actual and actual.lower() != KNOWN_SHA256:
        raise ValueError("Ghidra DLL hash differs from the known FM27 build")
    if not isinstance(report.get("functions"), list):
        raise ValueError("missing Ghidra function inventory")
    return {entry["name"]: entry for entry in report["functions"]}


def audit_native_contract(report: dict) -> dict:
    """Extract evidence links without trusting unverified host/ABI state."""
    functions = _validate(report)
    edges = []
    for src, dst, role in RESEARCH_EDGES:
        source = functions.get(src)
        target = functions.get(dst)
        observed = False
        if source and target and target.get("function"):
            target_entry = target["function"].get("entry_rva")
            observed = any(
                out.get("target_function_rva") == target_entry
                or out.get("target_rva") == target.get("requested_rva")
                for out in source.get("outgoing", [])
            )
        edges.append({
            "role": role,
            "caller": src,
            "callee": dst,
            "observed_direct": observed,
        })
    targets = {}
    for key in ("fixture_factory", "prepare_candidate", "ordinary_run_caller",
                "play_to_end", "match_reader"):
        item = functions.get(key)
        if item is None:
            targets[key] = {"found": False}
            continue
        fn = item.get("function")
        targets[key] = {
            "found": bool(fn),
            "exact_entry": item.get("exact_function_entry", False),
            "calling_convention": fn.get("calling_convention") if fn else None,
            "database_parameter_count": len(fn.get("database_parameters", [])) if fn else None,
            "decompilation": item.get("decompilation", {}).get("status"),
            "incoming_reference_count_in_export": len(item.get("incoming", [])),
        }
    run = functions.get("ordinary_run_caller", {})
    mode1_calls = []
    target = functions.get("play_to_end", {})
    target_rva = target.get("requested_rva")
    for call in run.get("high_pcode_calls", []):
        if call.get("target_rva") == target_rva:
            mode1_calls.append({
                "callsite_rva": call.get("callsite_rva"),
                "argument_count": call.get("argument_count"),
                "pcode_arguments": call.get("pcode_arguments"),
            })
    matched = sum(edge["observed_direct"] for edge in edges)
    return {
        "build_hash_verified": report.get("ghidra_executable_sha256") == KNOWN_SHA256,
        "function_inventory": targets,
        "direct_lifecycle_edges_observed": matched,
        "direct_lifecycle_edges_checked": len(edges),
        "edges": edges,
        "ordinary_caller_to_play_high_pcode": mode1_calls[:8],
        "native_execution_ready": False,
        "unresolved_blockers": [
            "No validated authorized initialized native host or invocation boundary",
            "Fixture/tactic pointer ownership and mutation contract unknown",
            "Native ABI and thread/TLS/global dependency closure not confirmed",
            "Setup flags and deterministic seed/reset behavior not validated",
            "No successfully executed one-match native round-trip or safe cleanup",
        ],
        "interpretation": (
            "Direct call evidence is static only; absent calls can be thunks, "
            "indirect edges, or limited Ghidra analysis. Even all links passing "
            "does not demonstrate a safe callable API or runnable FM27 simulator."
        ),
    }
