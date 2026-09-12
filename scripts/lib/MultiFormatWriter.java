package lib;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Dispatches a populated {@link ReportModel.ReportData} to every requested renderer.
 *
 * The orchestrator passes the selected format set and a logging callback; this class owns
 * the format-name aliases and the base-path → extension mapping.
 */
public class MultiFormatWriter {

    /** Writes every requested format. {@code log} receives one line per artifact produced. */
    public static void writeAll(String basePath,
                                Set<String> formats,
                                ReportModel.ReportData d,
                                Consumer<String> log) throws IOException {
        boolean all = formats.contains("all");

        if (all || formats.contains("txt")) {
            File f = new File(basePath + ".txt");
            TextReportWriter.write(f, d);
            log.accept("[+] Text report: " + f.getAbsolutePath());
        }
        if (all || formats.contains("json")) {
            File f = new File(basePath + ".json");
            JsonReportWriter.write(f, d);
            log.accept("[+] JSON report: " + f.getAbsolutePath());
        }
        if (all || formats.contains("md")) {
            File f = new File(basePath + ".md");
            MarkdownReportWriter.write(f, d);
            log.accept("[+] Markdown report: " + f.getAbsolutePath());
        }
        if (all || formats.contains("html")) {
            File f = new File(basePath + ".html");
            HtmlReportWriter.write(f, d);
            log.accept("[+] HTML report: " + f.getAbsolutePath());
        }
        if (all || formats.contains("yar") || formats.contains("yara")) {
            File f = new File(basePath + ".yar");
            writeYara(f, d);
            log.accept("[+] YARA rule: " + f.getAbsolutePath());
        }
        if (all || formats.contains("sarif")) {
            File f = new File(basePath + ".sarif");
            writeSarif(f, d);
            log.accept("[+] SARIF report: " + f.getAbsolutePath());
        }
        if (all || formats.contains("misp")) {
            File f = new File(basePath + ".misp.json");
            writeMisp(f, d);
            log.accept("[+] MISP report: " + f.getAbsolutePath());
        }
    }

    /** Strips a report extension the caller may have passed so every renderer appends its own. */
    public static String stripKnownExtension(String path) {
        for (String ext : new String[]{".txt", ".json", ".md", ".html", ".sarif", ".yar"}) {
            if (path.endsWith(ext)) {
                return path.substring(0, path.length() - ext.length());
            }
        }
        return path;
    }

    private static void writeYara(File file, ReportModel.ReportData d) throws IOException {
        List<String> iocStrings = new ArrayList<>();
        for (ReportModel.IocFinding ioc : d.iocFindings) {
            iocStrings.add(ioc.value);
        }

        List<String> hexSigs = new ArrayList<>();
        Listing listing = d.program.getListing();
        int sigLimit = Math.min(3, d.prioritizedFunctions.size());
        for (int i = 0; i < sigLimit; i++) {
            ReportModel.FunctionScore fs = d.prioritizedFunctions.get(i);
            InstructionIterator instrs = listing.getInstructions(fs.function.getBody(), true);
            StringBuilder hexBytes = new StringBuilder();
            int bCount = 0;
            while (instrs.hasNext() && bCount < 16) {
                Instruction instr = instrs.next();
                for (int b = 0; b < instr.getLength() && bCount < 16; b++) {
                    try {
                        hexBytes.append(String.format("%02x ", instr.getByte(b) & 0xFF));
                        bCount++;
                    } catch (Exception ignored) {}
                }
            }
            if (bCount >= 8) {
                hexSigs.add(hexBytes.toString().trim());
            }
        }

        YaraGenerator.generateRule(
                file,
                d.program.getName(),
                d.program.getExecutableMD5(),
                d.program.getExecutableSHA256(),
                d.imphash,
                d.riskScore,
                d.totalInitializedBytes,
                iocStrings,
                hexSigs
        );
    }

    private static void writeSarif(File file, ReportModel.ReportData d) throws IOException {
        List<SarifExporter.Finding> sarifFindings = new ArrayList<>();
        for (HeuristicScorer.ThreatIndicator ti : d.threatIndicators) {
            String ruleId = (ti.mitreId != null && !ti.mitreId.isEmpty())
                    ? ti.mitreId
                    : "SEC-" + ti.category.toUpperCase().replaceAll("[^A-Z0-9]", "-");
            String level = ti.weight >= 20 ? "error" : (ti.weight >= 10 ? "warning" : "note");
            sarifFindings.add(new SarifExporter.Finding(ruleId, ti.category, ti.description, "0x0", level));
        }
        SarifExporter.exportSarif(file, d.program.getName(), sarifFindings);
    }

    private static void writeMisp(File file, ReportModel.ReportData d) throws IOException {
        List<IocExtractor.IocFinding> allIocs = new ArrayList<>();
        for (ReportModel.IocFinding i : d.iocFindings) {
            allIocs.add(new IocExtractor.IocFinding(i.type, i.value, i.address, i.context));
        }
        MispExporter.exportMisp(
                file,
                d.program.getName(),
                d.program.getExecutableMD5(),
                d.program.getExecutableSHA256(),
                d.imphash,
                d.riskScore,
                d.riskLevel,
                allIocs,
                null
        );
    }
}
