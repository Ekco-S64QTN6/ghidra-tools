package lib;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.*;

/**
 * Shared data model for the report pipeline.
 *
 * ExportFullReport populates a {@link ReportData} during its analysis passes; every
 * renderer under lib/ consumes that single container instead of reaching back into
 * the orchestrator. Keeping the structures here is what lets the writers live in
 * their own compilation units.
 */
public class ReportModel {

    public static class BlockInfo {
        public String name;
        public String start;
        public String end;
        public long size;
        public String perms;
        public String type;
        public double entropy;
        public boolean isHighEntropy;
        public boolean isRwx;
        public String packerHint = "";
        public String comment = "";
    }

    public static class ImportEntry {
        public String library;
        public String function;
        public String mitreTechnique = null;
        public String threatCategory = null;
    }

    public static class ExportEntry {
        public String name;
        public String address;
    }

    public static class IocFinding {
        public String type;
        public String value;
        public String address;
        public String context = "";
    }

    public static class FunctionScore {
        public Function function;
        public int score;
        public int refCount;
        public int callCount;
        public int suspiciousApiCallCount;
        public long instructionCount;
        public String decompiledCode = null;
    }

    /** Everything a renderer needs to produce a report, in any format. */
    public static class ReportData {
        public Program program;
        public String formatLabel = "Binary";
        public boolean isSnes = false;
        public boolean fullDisasm = false;
        public String imphash = null;

        public int riskScore = 0;
        public String riskLevel = "LOW";
        public final List<HeuristicScorer.ThreatIndicator> threatIndicators = new ArrayList<>();

        public final List<BlockInfo> memoryBlocks = new ArrayList<>();
        public final Map<String, List<ImportEntry>> importsByLib = new LinkedHashMap<>();
        public final List<ImportEntry> suspiciousImports = new ArrayList<>();
        public final List<ExportEntry> exportsList = new ArrayList<>();
        public final List<IocFinding> iocFindings = new ArrayList<>();
        public final List<String> definedStringsList = new ArrayList<>();
        public final List<FunctionScore> prioritizedFunctions = new ArrayList<>();
        public final Map<String, Integer> topXRefs = new LinkedHashMap<>();

        public long totalDisassembledBytes = 0;
        public long totalInitializedBytes = 0;
        public double codeCoverage = 0.0;

        public final List<ShellcodeDetector.ShellcodeFinding> shellcodeFindings = new ArrayList<>();
        public final List<StackStringDetector.StackString> stackStrings = new ArrayList<>();
        public List<EmulatorDeobfuscator.DeobfuscatedString> deobfuscatedStrings = new ArrayList<>();

        public SnesAnalyzer.CartridgeHeader snesHeader = null;
        public List<SnesAnalyzer.MmioAccess> snesMmioAccesses = new ArrayList<>();
        public List<SnesAnalyzer.DmaChannelUsage> snesDmaChannels = new ArrayList<>();
    }
}
