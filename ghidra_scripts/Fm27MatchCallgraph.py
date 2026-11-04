# -*- coding: utf-8 -*-
#@author FM Match Sim
#@category FM27
#@description Read-only FM27 native fixture/prepare/play caller and ABI inventory.
#
# Run against an already imported, analyzed game_plugin.dll in Ghidra's
# Script Manager. It does not execute native code or modify the program.
# Optional headless script argument: absolute path to destination JSON.
#
# Ghidra's built-in Jython 2.7 is sufficient; no pip dependencies.
#
import json
import os
from java.lang import Exception as JavaException
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

RESEARCH_SHA256 = "252ff8fb5b7a4a5a5464db6ba632e309eef9b6e65ffa992ae20575a189e66c6a"
RESEARCH_SIZE = 404308480
# All values are RVAs for the exact 2026-11-04 FM27 game_plugin.dll build.
TARGETS = [
    ("fixture_factory", 0xC33370),
    ("fixture_prep_helper", 0xC2EAF0),
    ("match_allocator", 0xA85270),
    ("match_constructor", 0x184400),
    ("match_builder", 0x351B2B0),
    ("builder_args", 0x42CAE30),
    ("builder_dispatch", 0x42EA6C0),
    ("prepare_candidate", 0x16B8DBD0),
    ("prepare_setup", 0x4963300),
    ("prepare_phase_ff", 0x4962E70),
    ("prepare_phase_zero", 0x4962690),
    ("ordinary_run_caller", 0xC30710),
    ("play_to_end", 0x4520BD0),
    ("one_step_caller", 0x27BB350),
    ("match_serializer", 0x49EF150),
    ("match_reader", 0x4973930),
    ("match_destructor", 0x4968820),
]

MAX_INCOMING_REFS = 24
MAX_OUTGOING_REFS = 96
MAX_INSTRUCTIONS_PER_FUNCTION = 100000
MAX_DECOMPILED_FUNCTIONS = 48
DECOMPILER_TIMEOUT_SECONDS = 15

base_address = currentProgram.getImageBase()
function_manager = currentProgram.getFunctionManager()
reference_manager = currentProgram.getReferenceManager()
listing = currentProgram.getListing()


def to_address(rva):
    return base_address.add(long(rva))


def rva_of(address):
    if address is None:
        return None
    if address.getAddressSpace() != base_address.getAddressSpace():
        return None
    return "0x%X" % (long(address.getOffset()) - long(base_address.getOffset()))


def get_function(address):
    fn = function_manager.getFunctionAt(address)
    if fn is None:
        fn = function_manager.getFunctionContaining(address)
    return fn


def parameter_list(fn):
    parameters = []
    try:
        for p in fn.getParameters():
            parameters.append({
                "name": str(p.getName()),
                "data_type": str(p.getDataType().getDisplayName()),
                "storage": str(p.getVariableStorage()),
                "source": str(p.getSource()),
            })
    except Exception as ex:
        return [{"error": str(ex)}]
    return parameters


def function_metadata(fn):
    if fn is None:
        return None
    try:
        prototype = str(fn.getPrototypeString(True, True))
    except Exception:
        prototype = None
    try:
        cc = str(fn.getCallingConventionName())
    except Exception:
        cc = None
    try:
        size = long(fn.getBody().getNumAddresses())
    except Exception:
        size = None
    return {
        "entry_rva": rva_of(fn.getEntryPoint()),
        "name": str(fn.getName()),
        "signature": prototype,
        "calling_convention": cc,
        "return_type": str(fn.getReturnType().getDisplayName()),
        "database_parameters": parameter_list(fn),
        "body_bytes": size,
    }


_decomp_cache = {}
_decomp_count = [0]
decompiler = DecompInterface()
decompiler.toggleCCode(False)
decompiler.toggleSyntaxTree(True)
decompiler.openProgram(currentProgram)


def decomp_summary(fn):
    """Collect metadata/high-pcode arguments, not copyrighted decompiled C."""
    if fn is None:
        return {"status": "no-function"}
    key = str(fn.getEntryPoint())
    if key in _decomp_cache:
        return _decomp_cache[key]
    if _decomp_count[0] >= MAX_DECOMPILED_FUNCTIONS:
        return {"status": "budget-exhausted"}
    _decomp_count[0] += 1
    result = {"status": "not-decompiled", "calls": []}
    try:
        decomp = decompiler.decompileFunction(fn, DECOMPILER_TIMEOUT_SECONDS, monitor)
        if not decomp.decompileCompleted() or decomp.getHighFunction() is None:
            result["status"] = "decompile-incomplete"
            result["error"] = str(decomp.getErrorMessage())[:200]
        else:
            high = decomp.getHighFunction()
            result["status"] = "decompiled"
            try:
                proto = high.getFunctionPrototype()
                result["inferred_parameter_count"] = int(proto.getNumParams())
            except Exception:
                pass
            iterator = high.getPcodeOps()
            count = 0
            while iterator.hasNext() and count < 60000:
                monitor.checkCancelled()
                count += 1
                op = iterator.next()
                if op.getOpcode() != PcodeOp.CALL:
                    continue
                address = op.getSeqnum().getTarget()
                args = []
                for index in range(1, min(op.getNumInputs(), 9)):
                    args.append(str(op.getInput(index))[:100])
                dest = op.getInput(0)
                result["calls"].append({
                    "callsite_rva": rva_of(address),
                    "target_rva": rva_of(dest.getAddress()),
                    "argument_count": int(op.getNumInputs()) - 1,
                    "pcode_arguments": args,
                })
                if len(result["calls"]) >= MAX_OUTGOING_REFS:
                    break
            result["pcode_ops_examined"] = count
    except Exception as ex:
        result["status"] = "decompile-error"
        result["error"] = str(ex)[:200]
    _decomp_cache[key] = result
    return result


def incoming_refs(address):
    incoming = []
    refs = reference_manager.getReferencesTo(address)
    while refs.hasNext() and len(incoming) < MAX_INCOMING_REFS:
        monitor.checkCancelled()
        ref = refs.next()
        ref_type = ref.getReferenceType()
        if not (ref_type.isCall() or ref_type.isJump()):
            continue
        callsite = ref.getFromAddress()
        caller = get_function(callsite)
        instruction = listing.getInstructionAt(callsite)
        entry = {
            "callsite_rva": rva_of(callsite),
            "reference_type": str(ref_type),
            "caller": function_metadata(caller) if caller is not None else None,
            "instruction": str(instruction)[:160] if instruction else None,
        }
        if caller is not None:
            dec = decomp_summary(caller)
            matched = [
                item for item in dec.get("calls", [])
                if item["callsite_rva"] == entry["callsite_rva"]
            ]
            if matched:
                entry["high_pcode_call_arguments"] = matched[:2]
            entry["caller_decompile_status"] = dec["status"]
        incoming.append(entry)
    return incoming


def outgoing_refs(fn):
    if fn is None:
        return []
    outgoing = []
    instructions = listing.getInstructions(fn.getBody(), True)
    count = 0
    while instructions.hasNext() and count < MAX_INSTRUCTIONS_PER_FUNCTION:
        monitor.checkCancelled()
        ins = instructions.next()
        count += 1
        flow = ins.getFlowType()
        if not (flow.isCall() or flow.isJump()):
            continue
        refs = reference_manager.getReferencesFrom(ins.getAddress())
        for ref in refs:
            rt = ref.getReferenceType()
            if not (rt.isCall() or rt.isJump()):
                continue
            to = ref.getToAddress()
            target_fn = get_function(to)
            outgoing.append({
                "callsite_rva": rva_of(ins.getAddress()),
                "target_rva": rva_of(to),
                "target_function_rva": (
                    rva_of(target_fn.getEntryPoint()) if target_fn else None
                ),
                "target_name": (str(target_fn.getName()) if target_fn else None),
                "reference_type": str(rt),
            })
            if len(outgoing) >= MAX_OUTGOING_REFS:
                break
        if len(outgoing) >= MAX_OUTGOING_REFS:
            break
    return outgoing


def validate_program():
    sha = str(currentProgram.getExecutableSHA256() or "").lower()
    if sha and sha != RESEARCH_SHA256:
        raise ValueError("WRONG FM27 BUILD: Ghidra SHA256 %s" % sha)
    name = str(currentProgram.getName()).lower()
    if not name.endswith("game_plugin.dll"):
        raise ValueError("Expected imported game_plugin.dll, got %s" % name)
    return sha


def main():
    sha = validate_program()
    args = list(getScriptArgs())
    if args:
        destination = args[0]
    else:
        destination = askFile("Save private FM27 native callgraph JSON", "Save").getAbsolutePath()
    dest_dir = os.path.dirname(destination)
    if dest_dir and not os.path.isdir(dest_dir):
        os.makedirs(dest_dir)
    output = {
        "schema_version": 1,
        "project_file": str(currentProgram.getName()),
        "image_base": str(base_address),
        "ghidra_executable_sha256": sha if sha else None,
        "expected_sha256": RESEARCH_SHA256,
        "sha_verification": "matched" if sha else "missing-verify-manually",
        "read_only": True,
        "native_code_executed": False,
        "functions": [],
        "notes": [
            "Static findings only; Ghidra signatures/pcode are inferred, not a tested ABI.",
            "Missing cross-references may indicate a thunk or indirect call.",
            "No game process was attached or modified.",
            "No validated runtime host, fixture ownership or simulation result is implied.",
        ],
    }
    for name, rva in TARGETS:
        monitor.checkCancelled()
        address = to_address(rva)
        fn = get_function(address)
        target = {
            "name": name,
            "requested_rva": "0x%X" % rva,
            "exact_function_entry": bool(fn and fn.getEntryPoint().equals(address)),
            "function": function_metadata(fn),
            "incoming": incoming_refs(address),
            "outgoing": outgoing_refs(fn),
        }
        if fn is not None:
            dec = decomp_summary(fn)
            target["decompilation"] = {
                key: value for key, value in dec.items() if key != "calls"
            }
            target["high_pcode_calls"] = dec.get("calls", [])
        else:
            target["decompilation"] = {"status": "no-function"}
            target["high_pcode_calls"] = []
        output["functions"].append(target)
        println("FM27: %s 0x%X entry=%s callers=%d callees=%d"
                % (name, rva, target["exact_function_entry"],
                   len(target["incoming"]), len(target["outgoing"])))
    decompiler.dispose()
    with open(destination, "w") as fd:
        fd.write(json.dumps(output, indent=2, sort_keys=True))
        fd.write("\n")
    println("FM27: wrote private read-only callgraph to %s" % destination)


main()
