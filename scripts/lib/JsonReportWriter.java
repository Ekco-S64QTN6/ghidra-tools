package lib;

import ghidra.program.model.listing.Program;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import static lib.ReportFormat.escapeJson;

/** Renders the machine-readable report (.json) consumed by the SQLite indexer, diff, and SOAR pipelines. */
public class JsonReportWriter {

    public static void write(File file, ReportModel.ReportData d) throws IOException {
        file.getParentFile().mkdirs();
        Program p = d.program;
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
            out.println("{");
            out.println("  \"file\": \"" + escapeJson(p.getName()) + "\",");
            out.println("  \"format\": \"" + escapeJson(p.getExecutableFormat()) + "\",");
            out.println("  \"format_label\": \"" + escapeJson(d.formatLabel) + "\",");
            out.println("  \"generated\": \"" + new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX").format(new Date()) + "\",");
            out.println("  \"hashes\": {");
            out.println("    \"md5\": \"" + escapeJson(p.getExecutableMD5()) + "\",");
            out.println("    \"sha256\": \"" + escapeJson(p.getExecutableSHA256()) + "\"");
            out.println("  },");
            out.println("  \"architecture\": {");
            out.println("    \"language\": \"" + escapeJson(p.getLanguage().getLanguageDescription().getDescription()) + "\",");
            out.println("    \"language_id\": \"" + escapeJson(p.getLanguageID().toString()) + "\",");
            out.println("    \"compiler_spec\": \"" + escapeJson(p.getCompilerSpec().getCompilerSpecID().getIdAsString()) + "\",");
            out.println("    \"endianness\": \"" + (p.getLanguage().isBigEndian() ? "big" : "little") + "\",");
            out.println("    \"pointer_size_bits\": " + (p.getDefaultPointerSize() * 8));
            out.println("  },");
            out.println("  \"threat_summary\": {");
            out.println("    \"risk_score\": " + d.riskScore + ",");
            out.println("    \"risk_level\": \"" + escapeJson(d.riskLevel) + "\",");
            out.println("    \"indicators\": [");
            for (int i = 0; i < d.threatIndicators.size(); i++) {
                HeuristicScorer.ThreatIndicator ti = d.threatIndicators.get(i);
                out.print("      {\"category\": \"" + escapeJson(ti.category) + "\", \"description\": \"" + escapeJson(ti.description) + "\", \"mitre_id\": " + (ti.mitreId != null ? "\"" + escapeJson(ti.mitreId) + "\"" : "null") + ", \"weight\": " + ti.weight + "}");
                out.println(i < d.threatIndicators.size() - 1 ? "," : "");
            }
            out.println("    ]");
            out.println("  },");

            out.println("  \"memory_blocks\": [");
            for (int i = 0; i < d.memoryBlocks.size(); i++) {
                ReportModel.BlockInfo b = d.memoryBlocks.get(i);
                out.print("    {\"name\": \"" + escapeJson(b.name) + "\", \"start\": \"" + escapeJson(b.start) + "\", \"end\": \"" + escapeJson(b.end) + "\", \"size\": " + b.size + ", \"perms\": \"" + escapeJson(b.perms) + "\", \"entropy\": " + String.format(Locale.US, "%.4f", b.entropy) + ", \"high_entropy\": " + b.isHighEntropy + ", \"rwx\": " + b.isRwx + ", \"packer\": \"" + escapeJson(b.packerHint) + "\"}");
                out.println(i < d.memoryBlocks.size() - 1 ? "," : "");
            }
            out.println("  ],");

            out.println("  \"suspicious_apis\": [");
            for (int i = 0; i < d.suspiciousImports.size(); i++) {
                ReportModel.ImportEntry imp = d.suspiciousImports.get(i);
                out.print("    {\"function\": \"" + escapeJson(imp.function) + "\", \"library\": \"" + escapeJson(imp.library) + "\", \"mitre\": \"" + escapeJson(imp.mitreTechnique) + "\", \"category\": \"" + escapeJson(imp.threatCategory) + "\"}");
                out.println(i < d.suspiciousImports.size() - 1 ? "," : "");
            }
            out.println("  ],");

            out.println("  \"iocs\": [");
            for (int i = 0; i < d.iocFindings.size(); i++) {
                ReportModel.IocFinding ioc = d.iocFindings.get(i);
                out.print("    {\"type\": \"" + escapeJson(ioc.type) + "\", \"value\": \"" + escapeJson(ioc.value) + "\", \"address\": \"" + escapeJson(ioc.address) + "\"}");
                out.println(i < d.iocFindings.size() - 1 ? "," : "");
            }
            out.println("  ],");

            out.println("  \"deobfuscated_strings\": [");
            for (int i = 0; i < d.deobfuscatedStrings.size(); i++) {
                EmulatorDeobfuscator.DeobfuscatedString ds = d.deobfuscatedStrings.get(i);
                out.print("    {\"address\": \"" + escapeJson(ds.address) + "\", \"function\": \"" + escapeJson(ds.functionName) + "\", \"method\": \"" + escapeJson(ds.method) + "\", \"value\": \"" + escapeJson(ds.value) + "\"}");
                out.println(i < d.deobfuscatedStrings.size() - 1 ? "," : "");
            }
            out.println("  ],");

            out.println("  \"top_functions\": [");
            int fLimit = Math.min(10, d.prioritizedFunctions.size());
            for (int i = 0; i < fLimit; i++) {
                ReportModel.FunctionScore fs = d.prioritizedFunctions.get(i);
                out.print("    {\"name\": \"" + escapeJson(fs.function.getName()) + "\", \"address\": \"" + escapeJson(fs.function.getEntryPoint().toString()) + "\", \"score\": " + fs.score + ", \"xrefs\": " + fs.refCount + ", \"instructions\": " + fs.instructionCount + "}");
                out.println(i < fLimit - 1 ? "," : "");
            }
            out.println("  ],");

            out.println("  \"analysis_stats\": {");
            out.println("    \"function_count\": " + d.prioritizedFunctions.size() + ",");
            out.println("    \"symbol_count\": " + p.getSymbolTable().getNumSymbols() + ",");
            out.println("    \"initialized_bytes\": " + d.totalInitializedBytes + ",");
            out.println("    \"disassembled_bytes\": " + d.totalDisassembledBytes + ",");
            out.println("    \"code_coverage_pct\": " + String.format(Locale.US, "%.2f", d.codeCoverage));
            out.println("  }");

            if (d.isSnes && d.snesHeader != null) {
                writeSnesSection(out, d);
            }
            out.println("}");
        }
    }

    private static void writeSnesSection(PrintWriter out, ReportModel.ReportData d) {
        out.println("  ,");
        out.println("  \"snes\": {");
        out.println("    \"title\": \"" + escapeJson(d.snesHeader.title) + "\",");
        out.println("    \"mapping_mode\": \"" + escapeJson(d.snesHeader.mappingMode) + "\",");
        out.println("    \"rom_type\": \"" + escapeJson(d.snesHeader.romType) + "\",");
        out.println("    \"rom_size\": \"" + escapeJson(d.snesHeader.romSize) + "\",");
        out.println("    \"valid_header\": " + d.snesHeader.valid + ",");
        out.println("    \"checksum\": " + d.snesHeader.checksum + ",");
        out.println("    \"complement\": " + d.snesHeader.complement + ",");
        out.println("    \"dma_channels\": [");
        List<SnesAnalyzer.DmaChannelUsage> activeChannels = new ArrayList<>();
        for (SnesAnalyzer.DmaChannelUsage cu : d.snesDmaChannels) {
            if (cu.active) activeChannels.add(cu);
        }
        for (int i = 0; i < activeChannels.size(); i++) {
            SnesAnalyzer.DmaChannelUsage cu = activeChannels.get(i);
            out.print("      {\"channel\": " + cu.channel + ", \"mode\": \"" + escapeJson(cu.getModeString()) + "\", \"targets\": [");
            int tj = 0;
            for (String t : cu.targetDescriptions) {
                out.print("\"" + escapeJson(t) + "\"" + (tj++ < cu.targetDescriptions.size() - 1 ? ", " : ""));
            }
            out.print("], \"table_pointers\": [");
            int pj = 0;
            for (String ptr : cu.tablePointers) {
                out.print("\"" + escapeJson(ptr) + "\"" + (pj++ < cu.tablePointers.size() - 1 ? ", " : ""));
            }
            out.print("], \"hits\": " + cu.accessCount + "}");
            out.println(i < activeChannels.size() - 1 ? "," : "");
        }
        out.println("    ],");
        out.println("    \"mmio_accesses\": [");
        for (int i = 0; i < d.snesMmioAccesses.size(); i++) {
            SnesAnalyzer.MmioAccess ma = d.snesMmioAccesses.get(i);
            out.print("      {\"address\": " + ma.address + ", \"register\": \"" + escapeJson(ma.registerName) + "\", \"category\": \"" + escapeJson(ma.category) + "\", \"hits\": " + ma.accessCount + ", \"description\": \"" + escapeJson(ma.description) + "\"}");
            out.println(i < d.snesMmioAccesses.size() - 1 ? "," : "");
        }
        out.println("    ]");
        out.println("  }");
    }
}
