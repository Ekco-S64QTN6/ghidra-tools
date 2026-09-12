// Exports a comprehensive human-readable and machine-readable report of the analyzed program.
// Features: Threat Scoring Engine, Shannon Entropy & Packer Detection, MITRE ATT&CK API Tagging,
// IOC & String Intelligence, Priority-Based Disassembly, Decompiler C Pseudocode, and Multi-Format Export.
//
// This script is the orchestrator only: it drives the analysis passes and hands a populated
// ReportModel.ReportData to lib/MultiFormatWriter. All rendering lives under scripts/lib/.
//@category Analysis
//@author ghidra-tools

import ghidra.app.script.GhidraScript;
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

    private void analyzeFunctionsAndPriorities() {
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        FunctionIterator funcs = fm.getFunctions(true);

        while (funcs.hasNext()) {
            Function f = funcs.next();
            FunctionScore fs = new FunctionScore();
            fs.function = f;

            Reference[] refs = getReferencesTo(f.getEntryPoint());
            fs.refCount = (refs != null) ? refs.length : 0;

            Set<Function> called = f.getCalledFunctions(monitor);
            fs.callCount = (called != null) ? called.size() : 0;

            InstructionIterator instrs = listing.getInstructions(f.getBody(), true);
            long iCount = 0;
            int suspCount = 0;
            while (instrs.hasNext()) {
                Instruction instr = instrs.next();
                iCount++;
                data.totalDisassembledBytes += instr.getLength();
                for (int op = 0; op < instr.getNumOperands(); op++) {
                    for (Object obj : instr.getOpObjects(op)) {
                        if (obj instanceof Address) {
                            Function targetF = fm.getFunctionAt((Address) obj);
                            if (targetF != null && ApiTagger.isSuspicious(targetF.getName())) {
                                suspCount++;
                            }
                        }
                    }
                }
            }
            fs.instructionCount = iCount;
            fs.suspiciousApiCallCount = suspCount;

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
