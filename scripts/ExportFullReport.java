// Exports a comprehensive human-readable and machine-readable report of the analyzed program.
// Features: Threat Scoring Engine, Shannon Entropy & Packer Detection, MITRE ATT&CK API Tagging,
// IOC & String Intelligence, Priority-Based Disassembly, Decompiler C Pseudocode, and Multi-Format Export.
//
// This script is the orchestrator only: it drives the analysis passes and hands a populated
// ReportModel.ReportData to lib/MultiFormatWriter. All rendering lives under scripts/lib/.
//@category Analysis
//@author ghidra-tools

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.NewFunctionStackAnalysisCmd;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import lib.ApiTagger;
import lib.DecompilerExporter;
import lib.EmulatorDeobfuscator;
import lib.EntropyAnalyzer;
import lib.HeuristicScorer;
import lib.ImphashCalculator;
import lib.IocExtractor;
import lib.MultiFormatWriter;
import lib.ReportModel;
import lib.ShellcodeDetector;
import lib.SnesAnalyzer;
import lib.StackStringDetector;

import lib.HeuristicScorer.ThreatIndicator;
import lib.ReportModel.BlockInfo;
import lib.ReportModel.ExportEntry;
import lib.ReportModel.FunctionScore;
import lib.ReportModel.ImportEntry;
import lib.ReportModel.IocFinding;
import lib.ReportModel.ReportData;

import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

import java.util.*;

public class ExportFullReport extends GhidraScript {

    private final ReportData data = new ReportData();

    private String baseOutputPath;
    private final Set<String> outputFormats = new HashSet<>();

    @Override
    protected void run() throws Exception {
        parseArguments();

        println("[+] Starting analysis for: " + currentProgram.getName());

        data.program = currentProgram;
        data.formatLabel = detectFormatLabel();
        loadDetectionProvenance();
        data.isSnes = isSNES();

        analyzeMemoryAndEntropy();
        if (data.isSnes) {
            seedSnesEntryPoints();
            analyzeSnesHardware();
        }
        analyzeImportsAndExports();
        data.imphash = ImphashCalculator.calculateImphash(currentProgram);
        analyzeStringsAndIocs();
        analyzeFunctionsAndPriorities();
        deobfuscateStrings();
        analyzeCrossReferences();
        computeThreatScore();

        MultiFormatWriter.writeAll(
                MultiFormatWriter.stripKnownExtension(baseOutputPath),
                outputFormats,
                data,
                this::println);
    }

    private void loadDetectionProvenance() {
        String detectedFormat = environmentValue("GHIDRA_DETECTED_FORMAT");
        if (detectedFormat == null) {
            return;
        }

        ReportModel.DetectionInfo info = new ReportModel.DetectionInfo();
        info.detectedFormat = detectedFormat;
        info.evidence = environmentValue("GHIDRA_DETECTION_EVIDENCE");
        info.processorLanguageId = environmentValue("GHIDRA_DETECTED_PROCESSOR");
        info.selectedProcessorLanguageId = environmentValue("GHIDRA_SELECTED_PROCESSOR");
        info.requestedLoader = environmentValue("GHIDRA_REQUESTED_LOADER");
        info.importStrategy = environmentValue("GHIDRA_IMPORT_STRATEGY");
        String flags = environmentValue("GHIDRA_DETECTION_ELF_FLAGS");
        if (flags != null) {
            try {
                info.elfFlags = Long.parseLong(flags);
            } catch (NumberFormatException e) {
                println("[!] Ignoring invalid ELF e_flags value supplied by detector metadata.");
            }
        }
        data.detection = info;
    }

    private String environmentValue(String name) {
        String value = System.getenv(name);
        return (value == null || value.isEmpty()) ? null : value;
    }

    private void parseArguments() {
        String[] args = getScriptArgs();
        if (args.length > 0 && !args[0].isEmpty()) {
            baseOutputPath = args[0];
        } else {
            baseOutputPath = System.getProperty("user.home") + "/github/ghidra-tools/output/"
                    + currentProgram.getName().replaceAll("[^a-zA-Z0-9._-]", "_") + "_report";
        }

        String fmt = (args.length > 1 && !args[1].isEmpty()) ? args[1].toLowerCase() : "all";
        for (String f : fmt.split(",")) {
            outputFormats.add(f.trim());
        }

        if (args.length > 2 && args[2].contains("--full-disasm")) {
            data.fullDisasm = true;
        }
    }

    // --- Format & Target Detection ---

    private String detectFormatLabel() {
        String fmt = currentProgram.getExecutableFormat();
        String lang = currentProgram.getLanguageID().toString().toLowerCase();
        if (fmt == null) fmt = "";

        if (fmt.contains("Portable Executable") || fmt.toUpperCase().contains("PE32"))
            return "PE Executable";
        if (fmt.contains("Executable and Linking Format") || fmt.toUpperCase().contains("ELF"))
            return "ELF Binary";
        if (fmt.toLowerCase().contains("macho") || fmt.contains("Mac OS X"))
            return "Mach-O Binary";
        if (fmt.toLowerCase().contains("snes") || lang.contains("65816"))
            return "SNES ROM";
        if (fmt.toLowerCase().contains("raw"))
            return "Raw Binary";
        return fmt.isEmpty() ? "Binary" : fmt;
    }

    private boolean isSNES() {
        String lang = currentProgram.getLanguageID().toString().toLowerCase();
        String fmt = (currentProgram.getExecutableFormat() != null) ? currentProgram.getExecutableFormat().toLowerCase() : "";
        return lang.contains("65816") || fmt.contains("snes");
    }

    // --- Entropy & Packer Analysis ---

    private void analyzeMemoryAndEntropy() {
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            BlockInfo info = new BlockInfo();
            info.name = block.getName();
            info.start = block.getStart().toString();
            info.end = block.getEnd().toString();
            info.size = block.getSize();
            info.perms = (block.isRead() ? "R" : "-")
                    + (block.isWrite() ? "W" : "-")
                    + (block.isExecute() ? "X" : "-")
                    + (block.isVolatile() ? "V" : "-");
            info.type = block.isInitialized() ? "Initialized" : "Uninitialized";
            if (block.isMapped()) info.type = "Mapped";
            if (block.isOverlay()) info.type = "Overlay";
            info.comment = block.getComment() != null ? block.getComment() : "";

            if (block.isInitialized()) {
                data.totalInitializedBytes += block.getSize();
                info.entropy = EntropyAnalyzer.calculateBlockEntropy(block);
                if (EntropyAnalyzer.isHighEntropy(info.entropy)) {
                    info.isHighEntropy = true;
                    data.threatIndicators.add(new ThreatIndicator("Packer/Obfuscation",
                            "High-entropy section (" + info.name + ": " + String.format("%.2f", info.entropy) + " / 8.00) — likely packed or encrypted",
                            "T1027.002", 25));
                }

                info.packerHint = EntropyAnalyzer.detectPacker(info.name);
                if (!info.packerHint.isEmpty()) {
                    data.threatIndicators.add(new ThreatIndicator("Packer",
                            info.packerHint + " signature detected in section name: " + info.name, "T1027.002", 20));
                }
            }

            if (block.isRead() && block.isWrite() && block.isExecute()) {
                info.isRwx = true;
                data.threatIndicators.add(new ThreatIndicator("Permissions",
                        "RWX memory block detected: " + info.name + " (" + info.start + " - " + info.end + ") — possible shellcode staging",
                        "T1055", 20));
            }

            if (block.isInitialized()) {
                List<ShellcodeDetector.ShellcodeFinding> scHits = ShellcodeDetector.scanBlock(block);
                for (ShellcodeDetector.ShellcodeFinding hit : scHits) {
                    data.shellcodeFindings.add(hit);
                    data.threatIndicators.add(new ThreatIndicator("Shellcode / Staging", hit.description, "T1055", hit.severityWeight));
                }
            }

            data.memoryBlocks.add(info);
        }
    }

    /**
     * Disassembles from every populated 65816 interrupt vector.
     *
     * A raw binary import gives Ghidra no entry points, so auto-analysis leaves a
     * ROM almost entirely undisassembled and the MMIO/DMA scans below find nothing
     * to read. Seeding the handlers gives the analyzer the roots it needs.
     */
    private void seedSnesEntryPoints() {
        int seeded = 0;
        for (SnesAnalyzer.VectorTarget v : SnesAnalyzer.readVectors(currentProgram)) {
            try {
                disassemble(v.target);
                if (getFunctionAt(v.target) == null) {
                    createFunction(v.target, v.name);
                }
                seeded++;
            } catch (Exception e) {
                println("[!] Could not seed " + v.name + " @ " + v.target + ": " + e.getMessage());
            }
        }
        if (seeded > 0) {
            println("[+] Seeded disassembly from " + seeded + " SNES interrupt vector(s)");
        }
    }

    // --- SNES Cartridge, MMIO & DMA ---

    private void analyzeSnesHardware() {
        MemoryBlock firstBlock = null;
        if (!data.memoryBlocks.isEmpty()) {
            firstBlock = currentProgram.getMemory().getBlock(data.memoryBlocks.get(0).name);
        }
        if (firstBlock == null) {
            MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
            if (blocks != null && blocks.length > 0) firstBlock = blocks[0];
        }
        data.snesHeader = SnesAnalyzer.parseHeader(firstBlock);
        data.snesMmioAccesses = SnesAnalyzer.scanMmioAccesses(currentProgram.getListing());
        data.snesDmaChannels = SnesAnalyzer.scanDmaChannels(currentProgram.getListing());
    }

    // --- Imports & Exports Analysis ---

    private void analyzeImportsAndExports() {
        ExternalManager em = currentProgram.getExternalManager();
        String[] libs = em.getExternalLibraryNames();
        for (String lib : libs) {
            List<ImportEntry> libEntries = new ArrayList<>();
            ExternalLocationIterator locs = em.getExternalLocations(lib);
            while (locs.hasNext()) {
                ExternalLocation loc = locs.next();
                ImportEntry entry = new ImportEntry();
                entry.library = lib;
                entry.function = loc.getLabel();

                String baseFunc = entry.function.replaceAll("(A|W|Ex|ExA|ExW)$", "");
                ApiTagger.ApiTag tag = ApiTagger.getTag(entry.function);
                if (tag == null) tag = ApiTagger.getTag(baseFunc);

                if (tag != null) {
                    entry.mitreTechnique = tag.technique;
                    entry.threatCategory = tag.category;
                    data.suspiciousImports.add(entry);
                    data.threatIndicators.add(new ThreatIndicator("Suspicious API",
                            "Imported " + entry.library + "!" + entry.function + " (" + entry.threatCategory + ")",
                            entry.mitreTechnique, tag.weight));
                }

                libEntries.add(entry);
            }
            if (!libEntries.isEmpty()) {
                data.importsByLib.put(lib, libEntries);
            }
        }

        SymbolTable st = currentProgram.getSymbolTable();
        AddressIterator entryAddrs = st.getExternalEntryPointIterator();
        while (entryAddrs.hasNext()) {
            Address a = entryAddrs.next();
            Symbol s = st.getPrimarySymbol(a);
            ExportEntry exp = new ExportEntry();
            exp.address = a.toString();
            exp.name = (s != null) ? s.getName() : "entry";
            data.exportsList.add(exp);
        }
    }

    // --- Strings & IOC Intelligence ---

    private void analyzeStringsAndIocs() {
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            Data d = dataIter.next();
            if (!d.hasStringValue()) continue;
            Object val = d.getValue();
            if (val == null) continue;
            String str = val.toString().trim();
            if (str.length() <= 2) continue;

            String category = IocExtractor.classifyString(str);
            String preview = str.length() > 70 ? str.substring(0, 67) + "..." : str;
            String callContext = buildCallContext(d.getAddress());

            data.definedStringsList.add(String.format("%-14s [%-13s] \"%s\"%s", d.getAddress(), category, preview, callContext));

            for (IocExtractor.IocFinding h : IocExtractor.scanString(str, d.getAddress().toString())) {
                IocFinding ioc = new IocFinding();
                ioc.type = h.type;
                ioc.value = h.value;
                ioc.address = h.address;
                ioc.context = h.context;
                data.iocFindings.add(ioc);
                addIocThreatIndicator(h);
            }
        }
    }

    /** Renders the three instructions leading up to the first reference to {@code target}. */
    private String buildCallContext(Address target) {
        Reference[] refs = getReferencesTo(target);
        if (refs == null || refs.length == 0) return "";
        Instruction refInstr = currentProgram.getListing().getInstructionAt(refs[0].getFromAddress());
        if (refInstr == null) return "";

        Instruction p1 = refInstr.getPrevious();
        Instruction p2 = (p1 != null) ? p1.getPrevious() : null;
        StringBuilder ctx = new StringBuilder();
        if (p2 != null) ctx.append(p2).append("; ");
        if (p1 != null) ctx.append(p1).append("; ");
        ctx.append(refInstr);
        return " [Context: " + ctx + "]";
    }

    private void addIocThreatIndicator(IocExtractor.IocFinding h) {
        switch (h.type) {
            case "IPv4 Address":
                data.threatIndicators.add(new ThreatIndicator("IOC (Network)", "Public IP address in strings: " + h.value, "T1071", 15));
                break;
            case "URL":
                data.threatIndicators.add(new ThreatIndicator("IOC (Network)", "URL reference in strings: " + h.value, "T1071", 15));
                break;
            case "Registry Key":
                data.threatIndicators.add(new ThreatIndicator("IOC (Host)", "Windows Registry key: " + h.value, "T1112", 10));
                break;
            case "Base64 Decoded String":
                data.threatIndicators.add(new ThreatIndicator("Obfuscation", "Decoded ASCII string from Base64 payload", "T1027", 10));
                break;
            case "Hex Decoded String":
                data.threatIndicators.add(new ThreatIndicator("Obfuscation", "Decoded ASCII string from Hex payload", "T1027", 10));
                break;
            default:
                break;
        }
    }

    // --- Priority Scoring & Decompilation ---

    private void debugStackReferences(Function function, Listing listing) {
        println("[STACK-PROBE] function=" + function.getName()
                + " stackVariables=" + function.getStackFrame().getStackVariables().length);
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            String instructionText = instruction.toString().toUpperCase();
            if (!instructionText.contains("EBP") && !instructionText.contains("ESP")) continue;

            println("[STACK-PROBE] instruction=" + instruction.getAddress() + " " + instruction);
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                Reference primary = instruction.getPrimaryReference(operand);
                println("[STACK-PROBE] operand=" + operand
                        + " type=0x" + Integer.toHexString(instruction.getOperandType(operand))
                        + " primary=" + (primary == null ? "null"
                        : primary.getClass().getName() + "/" + primary.getReferenceType()
                        + "/stack=" + primary.isStackReference() + "/to=" + primary.getToAddress()));
            }
            for (Reference reference : instruction.getReferencesFrom()) {
                println("[STACK-PROBE] reference=" + reference.getClass().getName()
                        + " operand=" + reference.getOperandIndex()
                        + " type=" + reference.getReferenceType()
                        + " stack=" + reference.isStackReference()
                        + " to=" + reference.getToAddress());
            }
            PcodeOp[] pcode = instruction.getPcode();
            if (pcode == null) continue;
            for (PcodeOp operation : pcode) {
                if (operation == null || operation.getOpcode() != PcodeOp.STORE
                        || operation.getNumInputs() < 3) continue;
                Varnode value = operation.getInput(2);
                println("[STACK-PROBE] store=" + operation
                        + " valueConstant=" + value.isConstant()
                        + " valueSize=" + value.getSize()
                        + " valueOffset=0x" + Long.toHexString(value.getOffset()));
            }
        }
    }

    private void analyzeFunctionsAndPriorities() {
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        // Stack-reference records are not guaranteed to exist after the default
        // headless analyzers. Create them explicitly before the stack-string pass
        // so the detector can verify destination offsets instead of guessing from
        // mnemonics or immediate operands.
        AddressSet stackFunctionEntries = new AddressSet();
        FunctionIterator stackFunctions = fm.getFunctions(true);
        while (stackFunctions.hasNext()) {
            stackFunctionEntries.add(stackFunctions.next().getEntryPoint());
        }
        boolean stackAnalysisComplete = true;
        if (!stackFunctionEntries.isEmpty()) {
            NewFunctionStackAnalysisCmd stackAnalysis =
                    new NewFunctionStackAnalysisCmd(stackFunctionEntries, true);
            stackAnalysisComplete = stackAnalysis.applyTo(currentProgram, monitor);
            if (!stackAnalysisComplete) {
                println("[!] Ghidra stack-reference analysis was incomplete; stack-string recovery may be limited.");
            }
        }
        println("[STACK-PROBE] analysisComplete=" + stackAnalysisComplete
                + " functionEntries=" + stackFunctionEntries.getNumAddresses());

        FunctionIterator diagnosticFunctions = fm.getFunctions(true);
        while (diagnosticFunctions.hasNext()) {
            debugStackReferences(diagnosticFunctions.next(), listing);
        }

        FunctionIterator funcs = fm.getFunctions(true);

        while (funcs.hasNext()) {
            Function f = funcs.next();
            FunctionScore fs = new FunctionScore();
            fs.function = f;

            Reference[] refs = getReferencesTo(f.getEntryPoint());
            fs.refCount = (refs != null) ? refs.length : 0;

            Set<Function> called = f.getCalledFunctions(monitor);
            fs.callCount = (called != null) ? called.size() : 0;
            Set<String> recordedApiCalls = new HashSet<>();

            InstructionIterator instrs = listing.getInstructions(f.getBody(), true);
            long iCount = 0;
            while (instrs.hasNext()) {
                Instruction instr = instrs.next();
                iCount++;
                data.totalDisassembledBytes += instr.getLength();

                if (!instr.getFlowType().isCall()) continue;
                for (int op = 0; op < instr.getNumOperands(); op++) {
                    for (Object obj : instr.getOpObjects(op)) {
                        if (!(obj instanceof Address)) continue;
                        Address targetAddress = (Address) obj;
                        Function targetF = fm.getFunctionAt(targetAddress);
                        if (targetF != null) {
                            recordFunctionApiCall(targetF.getName(), targetF.getEntryPoint().toString(),
                                    instr.getAddress(), fs, recordedApiCalls);
                        } else {
                            Symbol targetSymbol = currentProgram.getSymbolTable().getPrimarySymbol(targetAddress);
                            if (targetSymbol != null) {
                                String apiName = targetSymbol.getName();
                                if (apiName.startsWith("__imp_")) apiName = apiName.substring(6);
                                recordFunctionApiCall(apiName, targetAddress.toString(),
                                        instr.getAddress(), fs, recordedApiCalls);
                            }
                        }
                    }
                }
            }

            // Call-graph references also resolve external functions reached through thunks.
            if (called != null) {
                for (Function targetF : called) {
                    if (targetF == null || !ApiTagger.isSuspicious(targetF.getName())) continue;
                    Reference[] apiRefs = getReferencesTo(targetF.getEntryPoint());
                    if (apiRefs == null) continue;
                    for (Reference apiRef : apiRefs) {
                        Address callSite = apiRef.getFromAddress();
                        if (f.getBody().contains(callSite) && apiRef.getReferenceType().isCall()) {
                            recordFunctionApiCall(targetF.getName(), targetF.getEntryPoint().toString(),
                                    callSite, fs, recordedApiCalls);
                        }
                    }
                }
            }

            fs.instructionCount = iCount;
            fs.suspiciousApiCallCount = fs.suspiciousApis.size();

            // Priority scoring heuristic
            fs.score = (fs.refCount * 3) + (fs.callCount * 2) + (fs.suspiciousApiCallCount * 20) + (int) Math.min(20, fs.instructionCount / 10);
            data.prioritizedFunctions.add(fs);

            for (StackStringDetector.StackString ss : StackStringDetector.scanFunction(f, listing)) {
                data.stackStrings.add(ss);
                data.threatIndicators.add(new ThreatIndicator("Obfuscation",
                        "Stack string reconstructed in " + f.getName() + ": \"" + ss.value + "\"", "T1027", 15));
            }
        }

        data.prioritizedFunctions.sort((a, b) -> Integer.compare(b.score, a.score));

        DecompilerExporter.decompileTop(currentProgram, data.prioritizedFunctions, monitor);

        if (data.totalInitializedBytes > 0) {
            data.codeCoverage = (data.totalDisassembledBytes * 100.0) / data.totalInitializedBytes;
        }
    }

    private void recordFunctionApiCall(
            String apiName,
            String targetAddress,
            Address callSite,
            FunctionScore score,
            Set<String> recorded
    ) {
        if (apiName == null || !ApiTagger.isSuspicious(apiName)) return;
        String callAddress = callSite.toString();
        if (!recorded.add(targetAddress + "|" + callAddress + "|" + apiName)) return;

        ReportModel.FunctionApiCall evidence = new ReportModel.FunctionApiCall();
        evidence.function = apiName;
        evidence.targetAddress = targetAddress;
        evidence.callSite = callAddress;
        score.suspiciousApis.add(evidence);
    }

    // --- P-Code Emulation Deobfuscation ---

    private void deobfuscateStrings() {
        List<Function> candidates = new ArrayList<>();
        for (FunctionScore fs : data.prioritizedFunctions) candidates.add(fs.function);

        data.deobfuscatedStrings = EmulatorDeobfuscator.deobfuscateCandidates(currentProgram, candidates, monitor);
        for (EmulatorDeobfuscator.DeobfuscatedString ds : data.deobfuscatedStrings) {
            data.threatIndicators.add(new ThreatIndicator("Deobfuscation",
                    "Deobfuscated string: \"" + ds.value + "\" (" + ds.method + ")", "T1027", 15));
        }
    }

    // --- Cross-Reference Hotspots ---

    private void analyzeCrossReferences() {
        FunctionManager fm = currentProgram.getFunctionManager();
        Map<Address, Integer> counts = new HashMap<>();
        ReferenceManager rm = currentProgram.getReferenceManager();
        AddressIterator refAddrs = rm.getReferenceDestinationIterator(currentProgram.getMemory(), true);
        while (refAddrs.hasNext()) {
            Address a = refAddrs.next();
            ReferenceIterator refs = rm.getReferencesTo(a);
            int refCount = 0;
            while (refs.hasNext()) {
                refs.next();
                refCount++;
            }
            if (refCount > 1) {
                counts.put(a, refCount);
            }
        }
        List<Map.Entry<Address, Integer>> list = new ArrayList<>(counts.entrySet());
        list.sort((a, b) -> b.getValue().compareTo(a.getValue()));
        int limit = Math.min(30, list.size());
        for (int i = 0; i < limit; i++) {
            Map.Entry<Address, Integer> e = list.get(i);
            Function f = fm.getFunctionAt(e.getKey());
            String name = (f != null) ? f.getName() : "(data/label)";
            data.topXRefs.put(e.getKey().toString() + " (" + name + ")", e.getValue());
        }
    }

    // --- Threat Scoring Engine ---

    private void computeThreatScore() {
        HeuristicScorer.ScoreResult res = HeuristicScorer.computeScore(data.threatIndicators, data.isSnes);
        data.riskScore = res.score;
        data.riskLevel = res.level;
    }
}
