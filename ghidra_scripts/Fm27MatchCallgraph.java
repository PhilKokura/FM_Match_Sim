// Read-only callgraph and inferred parameter inventory for the native FM27 match engine.
//@category FM27
//@author FM Match Sim

import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class Fm27MatchCallgraph extends GhidraScript {
    private static final String KNOWN_SHA256 =
        "252ff8fb5b7a4a5a5464db6ba632e309eef9b6e65ffa992ae20575a189e66c6a";
    private static final int MAX_INCOMING = 24;
    private static final int MAX_OUTGOING = 96;
    private static final int MAX_INSTRUCTIONS = 100000;
    private static final int MAX_PCODE = 60000;
    private static final int DECOMP_TIMEOUT_SECONDS = 12;

    // RVAs, not absolute virtual addresses; exact known FM27 DLL build only.
    private static final String[][] TARGETS = {
        {"fixture_play_candidate", "C2F820"},
        {"fixture_factory", "C33370"},
        {"fixture_prep_helper", "C2EAF0"},
        {"match_allocator", "A85270"},
        {"match_constructor", "184400"},
        {"match_builder", "351B2B0"},
        {"builder_args", "42CAE30"},
        {"builder_dispatch", "42EA6C0"},
        {"prepare_candidate", "16B8DBD0"},
        {"prepare_setup", "4963300"},
        {"prepare_phase_ff", "4962E70"},
        {"prepare_phase_zero", "4962690"},
        {"ordinary_run_caller", "C30710"},
        {"play_to_end", "4520BD0"},
        {"one_step_caller", "27BB350"},
        {"match_serializer", "49EF150"},
        {"match_reader", "4973930"},
        {"match_destructor", "4968820"}
    };

    // Decompile only the paths relevant to the first hosted-match experiment.
    private static final Set<String> DECOMPILE_TARGETS = new LinkedHashSet<String>(
        Arrays.asList("fixture_play_candidate", "fixture_factory", "match_builder", "builder_args",
                      "prepare_candidate", "ordinary_run_caller", "play_to_end",
                      "match_reader"));

    private Address imageBase;
    private FunctionManager functionManager;
    private ReferenceManager referenceManager;
    private Listing listing;
    private DecompInterface decompiler;

    private static Map<String, Object> obj(Object... alternating) {
        Map<String, Object> value = new LinkedHashMap<String, Object>();
        for (int index = 0; index < alternating.length; index += 2) {
            value.put((String) alternating[index], alternating[index + 1]);
        }
        return value;
    }

    private Address addressFor(String rva) {
        return imageBase.add(Long.parseUnsignedLong(rva, 16));
    }

    private String rva(Address address) {
        if (address == null || !address.getAddressSpace().equals(imageBase.getAddressSpace())) {
            return null;
        }
        return String.format("0x%X", address.getOffset() - imageBase.getOffset());
    }

    private Function functionAtOrContaining(Address addr) {
        Function function = functionManager.getFunctionAt(addr);
        return function != null ? function : functionManager.getFunctionContaining(addr);
    }

    private Object metadata(Function function) {
        if (function == null) {
            return null;
        }
        List<Object> params = new ArrayList<Object>();
        for (Parameter p : function.getParameters()) {
            params.add(obj("name", p.getName(),
                           "data_type", p.getDataType().getDisplayName(),
                           "storage", String.valueOf(p.getVariableStorage()),
                           "source", String.valueOf(p.getSource())));
        }
        String prototype;
        try {
            prototype = function.getPrototypeString(true, true);
        }
        catch (Exception exc) {
            prototype = null;
        }
        return obj("entry_rva", rva(function.getEntryPoint()),
                   "name", function.getName(),
                   "signature", prototype,
                   "calling_convention", function.getCallingConventionName(),
                   "return_type", function.getReturnType().getDisplayName(),
                   "database_parameters", params,
                   "body_bytes", function.getBody().getNumAddresses());
    }

    private List<Object> incoming(Address address) throws Exception {
        List<Object> results = new ArrayList<Object>();
        ReferenceIterator iterator = referenceManager.getReferencesTo(address);
        while (iterator.hasNext() && results.size() < MAX_INCOMING) {
            monitor.checkCancelled();
            Reference reference = iterator.next();
            if (!reference.getReferenceType().isCall() &&
                !reference.getReferenceType().isJump()) {
                continue;
            }
            Address from = reference.getFromAddress();
            Function caller = functionAtOrContaining(from);
            Instruction instruction = listing.getInstructionAt(from);
            results.add(obj(
                "callsite_rva", rva(from),
                "reference_type", String.valueOf(reference.getReferenceType()),
                "caller", metadata(caller),
                "instruction", instruction == null ? null : instruction.toString()));
        }
        return results;
    }

    private List<Object> outgoing(Function function) throws Exception {
        List<Object> results = new ArrayList<Object>();
        if (function == null) {
            return results;
        }
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        int inspected = 0;
        while (instructions.hasNext() && inspected < MAX_INSTRUCTIONS &&
               results.size() < MAX_OUTGOING) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            inspected++;
            if (!instruction.getFlowType().isCall() &&
                !instruction.getFlowType().isJump()) {
                continue;
            }
            for (Reference ref : referenceManager.getReferencesFrom(instruction.getAddress())) {
                if (!ref.getReferenceType().isCall() && !ref.getReferenceType().isJump()) {
                    continue;
                }
                Function target = functionAtOrContaining(ref.getToAddress());
                results.add(obj(
                    "callsite_rva", rva(instruction.getAddress()),
                    "target_rva", rva(ref.getToAddress()),
                    "target_function_rva", target == null ?
                        null : rva(target.getEntryPoint()),
                    "target_name", target == null ? null : target.getName(),
                    "reference_type", String.valueOf(ref.getReferenceType())));
                if (results.size() >= MAX_OUTGOING) {
                    break;
                }
            }
        }
        return results;
    }

    private Map<String, Object> decompile(Function function) throws Exception {
        if (function == null) {
            return obj("status", "no-function", "calls", new ArrayList<Object>());
        }
        try {
            DecompileResults result = decompiler.decompileFunction(
                function, DECOMP_TIMEOUT_SECONDS, monitor);
            if (!result.decompileCompleted() || result.getHighFunction() == null) {
                return obj("status", "decompile-incomplete",
                           "error", String.valueOf(result.getErrorMessage()),
                           "calls", new ArrayList<Object>());
            }
            HighFunction high = result.getHighFunction();
            List<Object> calls = new ArrayList<Object>();
            int seen = 0;
            java.util.Iterator<PcodeOpAST> instructions = high.getPcodeOps();
            while (instructions.hasNext() && seen < MAX_PCODE && calls.size() < MAX_OUTGOING) {
                monitor.checkCancelled();
                PcodeOpAST op = instructions.next();
                seen++;
                if (op.getOpcode() != PcodeOp.CALL) {
                    continue;
                }
                Varnode dest = op.getInput(0);
                List<Object> args = new ArrayList<Object>();
                for (int index = 1; index < Math.min(op.getNumInputs(), 9); index++) {
                    args.add(String.valueOf(op.getInput(index)));
                }
                calls.add(obj(
                    "callsite_rva", rva(op.getSeqnum().getTarget()),
                    "target_rva", dest == null ? null : rva(dest.getAddress()),
                    "argument_count", op.getNumInputs() - 1,
                    "pcode_arguments", args));
            }
            return obj("status", "decompiled",
                       "pcode_ops_examined", seen,
                       "calls", calls);
        }
        catch (Exception exc) {
            return obj("status", "decompile-error",
                       "error", exc.toString(),
                       "calls", new ArrayList<Object>());
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open game_plugin.dll in the CodeBrowser first.");
        }
        if (!currentProgram.getName().toLowerCase(Locale.ROOT).endsWith("game_plugin.dll")) {
            throw new IllegalStateException("Expected game_plugin.dll, not " +
                                            currentProgram.getName());
        }
        String sha = currentProgram.getExecutableSHA256();
        if (sha != null && !sha.isEmpty() && !KNOWN_SHA256.equalsIgnoreCase(sha)) {
            throw new IllegalStateException(
                "Wrong or changed FM27 build. Ghidra reports SHA-256 " + sha);
        }
        if (sha == null || sha.isEmpty()) {
            println("WARNING: Ghidra did not report DLL SHA-256; verify exact build manually.");
        }

        String[] args = getScriptArgs();
        File destination = (args != null && args.length > 0 && !args[0].isEmpty())
            ? new File(args[0])
            : askFile("Save private FM27 callgraph JSON", "Save");

        imageBase = currentProgram.getImageBase();
        functionManager = currentProgram.getFunctionManager();
        referenceManager = currentProgram.getReferenceManager();
        listing = currentProgram.getListing();
        decompiler = new DecompInterface();
        decompiler.toggleCCode(false);
        decompiler.toggleSyntaxTree(true);
        decompiler.openProgram(currentProgram);

        List<Object> functions = new ArrayList<Object>();
        try {
            for (String[] target : TARGETS) {
                monitor.checkCancelled();
                String name = target[0];
                Address addr = addressFor(target[1]);
                Function function = functionAtOrContaining(addr);
                boolean exact = function != null &&
                                function.getEntryPoint().equals(addr);
                List<Object> in = incoming(addr);
                List<Object> out = outgoing(function);

                Map<String, Object> decoded = DECOMPILE_TARGETS.contains(name)
                    ? decompile(function)
                    : obj("status", "not-selected",
                          "calls", new ArrayList<Object>());
                Object calls = decoded.remove("calls");
                functions.add(obj(
                    "name", name,
                    "requested_rva", rva(addr),
                    "exact_function_entry", exact,
                    "function", metadata(function),
                    "incoming", in,
                    "outgoing", out,
                    "decompilation", decoded,
                    "high_pcode_calls", calls));
                println("FM27 " + name + " entry=" + exact +
                        " callers=" + in.size() + " callees=" + out.size() +
                        " decompile=" + decoded.get("status"));
            }
        }
        finally {
            decompiler.dispose();
        }

        Map<String, Object> result = obj(
            "schema_version", 1,
            "project_file", currentProgram.getName(),
            "image_base", String.valueOf(imageBase),
            "ghidra_executable_sha256", sha == null || sha.isEmpty() ? null : sha,
            "expected_sha256", KNOWN_SHA256,
            "sha_verification", sha == null || sha.isEmpty() ? "missing-verify-manually" : "matched",
            "read_only", true,
            "native_code_executed", false,
            "functions", functions,
            "notes", Arrays.asList(
                "Static callgraph only. Signatures and high pcode are not validated ABIs.",
                "Missing direct references do not exclude thunk or indirect calls.",
                "No game process memory was changed or native match function executed."));

        File parent = destination.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("Cannot create output directory: " + parent);
        }
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(result);
        Files.write(destination.toPath(), (json + "\n").getBytes(StandardCharsets.UTF_8));
        println("FM27 native callgraph written to: " + destination.getAbsolutePath());
    }
}
