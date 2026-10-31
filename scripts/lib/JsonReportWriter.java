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
import java.util.Comparator;
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
            out.println("  \"schema_version\": \"1.0.0\",");
            out.println("  \"format\": \"" + escapeJson(p.getExecutableFormat()) + "\",");
            out.println("  \"format_label\": \"" + escapeJson(d.formatLabel) + "\",");
            if (d.detection != null) {
                writeDetection(out, d.detection);
            }
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

            // Preserve the complete static import surface separately from the
            // narrower suspicious_apis list used by threat scoring.
            List<ReportModel.ImportEntry> allStaticApis = new ArrayList<>();
            for (List<ReportModel.ImportEntry> libraryEntries : d.importsByLib.values()) {
                allStaticApis.addAll(libraryEntries);
            }
            allStaticApis.sort(
                    Comparator.comparing((ReportModel.ImportEntry entry) -> entry.library == null ? "" : entry.library,
                                    String.CASE_INSENSITIVE_ORDER)
                            .thenComparing(entry -> entry.function == null ? "" : entry.function,
                                    String.CASE_INSENSITIVE_ORDER)
            );
            out.println("  \"static_apis\": [");
            for (int i = 0; i < allStaticApis.size(); i++) {
                ReportModel.ImportEntry imp = allStaticApis.get(i);
                out.print("    {\"function\": \"" + escapeJson(imp.function)
                        + "\", \"library\": \"" + escapeJson(imp.library) + "\"}");
                out.println(i < allStaticApis.size() - 1 ? "," : "");
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

            out.println("  \"stack_strings\": [");
            for (int i = 0; i < d.stackStrings.size(); i++) {
                StackStringDetector.StackString ss = d.stackStrings.get(i);
                out.print("    {\"address\": \"" + escapeJson(ss.address)
                        + "\", \"function\": \"" + escapeJson(ss.functionName)
                        + "\", \"method\": \"" + escapeJson(ss.method)
                        + "\", \"value\": \"" + escapeJson(ss.value)
                        + "\", \"byte_count\": " + ss.byteCount
                        + ", \"stack_offset_start\": " + ss.stackOffsetStart
                        + ", \"stack_offset_end\": " + ss.stackOffsetEnd
                        + ", \"evidence\": \"" + escapeJson(ss.evidence) + "\"}");
                out.println(i < d.stackStrings.size() - 1 ? "," : "");
            }
            out.println("  ],");

            out.println("  \"function_api_evidence\": [");
            List<ReportModel.FunctionScore> apiEvidenceFunctions = new ArrayList<>();
            for (ReportModel.FunctionScore fs : d.prioritizedFunctions) {
                if (!fs.suspiciousApis.isEmpty()) apiEvidenceFunctions.add(fs);
            }
            for (int i = 0; i < apiEvidenceFunctions.size(); i++) {
                ReportModel.FunctionScore fs = apiEvidenceFunctions.get(i);
                out.println("    {");
                out.println("      \"function\": \"" + escapeJson(fs.function.getName()) + "\",");
                out.println("      \"address\": \"" + escapeJson(fs.function.getEntryPoint().toString()) + "\",");
                out.println("      \"suspicious_apis\": [");
                for (int j = 0; j < fs.suspiciousApis.size(); j++) {
                    ReportModel.FunctionApiCall api = fs.suspiciousApis.get(j);
                    out.print("        {\"function\": \"" + escapeJson(api.function)
                            + "\", \"target_address\": \"" + escapeJson(api.targetAddress)
                            + "\", \"call_site\": \"" + escapeJson(api.callSite) + "\"}");
                    out.println(j < fs.suspiciousApis.size() - 1 ? "," : "");
                }
                out.println("      ]");
                out.print("    }");
                out.println(i < apiEvidenceFunctions.size() - 1 ? "," : "");
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

    private static void writeDetection(PrintWriter out, ReportModel.DetectionInfo detection) {
        out.println("  \"detection\": {");
        out.println("    \"detected_format\": \"" + escapeJson(detection.detectedFormat) + "\",");
        out.println("    \"evidence\": " + nullableJsonString(detection.evidence) + ",");
        out.println("    \"processor_language_id\": " + nullableJsonString(detection.processorLanguageId) + ",");
        out.println("    \"selected_processor_language_id\": " + nullableJsonString(detection.selectedProcessorLanguageId) + ",");
        out.println("    \"requested_loader\": " + nullableJsonString(detection.requestedLoader) + ",");
        out.println("    \"import_strategy\": " + nullableJsonString(detection.importStrategy) + ",");
        out.println("    \"elf_flags\": " + (detection.elfFlags != null ? detection.elfFlags : "null"));
        out.println("  },");
    }

    private static String nullableJsonString(String value) {
        return value == null ? "null" : "\"" + escapeJson(value) + "\"";
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
