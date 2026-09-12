package lib;

import ghidra.program.model.listing.Program;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;

/** Renders the GitHub-flavored Markdown report (.md). */
public class MarkdownReportWriter {

    public static void write(File file, ReportModel.ReportData d) throws IOException {
        file.getParentFile().mkdirs();
        Program p = d.program;
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
            out.println("# Binary Analysis Report: " + p.getName());
            out.println();
            out.println("> **Format:** `" + p.getExecutableFormat() + "` | **Generated:** `" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z").format(new Date()) + "`");
            out.println();

            out.println("## Threat Triage Summary");
            out.println();
            out.printf("> **Risk Score:** `%d / 100` — **Level:** `%s`%n", d.riskScore, d.riskLevel);
            out.println(">");
            if (d.threatIndicators.isEmpty()) {
                out.println("> No overt threats detected.");
            } else {
                for (HeuristicScorer.ThreatIndicator ti : d.threatIndicators) {
                    out.printf("> - `%s` %s%n", ti.mitreId != null ? ti.mitreId : ti.category, ti.description);
                }
            }
            out.println();

            out.println("## Program Information");
            out.println();
            out.println("| Property | Value |");
            out.println("|---|---|");
            out.println("| **File Name** | `" + p.getName() + "` |");
            out.println("| **Architecture** | " + p.getLanguage().getLanguageDescription().getDescription() + " |");
            out.println("| **Compiler Spec** | `" + p.getCompilerSpec().getCompilerSpecID() + "` |");
            out.println("| **MD5** | `" + p.getExecutableMD5() + "` |");
            out.println("| **SHA-256** | `" + p.getExecutableSHA256() + "` |");
            out.println();

            out.println("## Memory Map & Shannon Entropy");
            out.println();
            out.println("| Block Name | Start | End | Size | Perms | Entropy | Status | Notes |");
            out.println("|---|---|---|---|---|---|---|---|");
            for (ReportModel.BlockInfo b : d.memoryBlocks) {
                String status = b.isHighEntropy ? "**PACKED/CRYPT**" : "Normal";
                String note = b.packerHint.isEmpty() ? (b.isRwx ? "⚠️ RWX" : "-") : "⚠️ " + b.packerHint;
                out.printf("| `%s` | `%s` | `%s` | %,d | `%s` | `%.2f` | %s | %s |%n",
                        b.name, b.start, b.end, b.size, b.perms, b.entropy, status, note);
            }
            out.println();

            if (!d.suspiciousImports.isEmpty()) {
                out.println("## Suspicious APIs & MITRE ATT&CK Mapping");
                out.println();
                out.println("| Function | Library | ATT&CK Technique | Threat Category |");
                out.println("|---|---|---|---|");
                for (ReportModel.ImportEntry imp : d.suspiciousImports) {
                    out.printf("| `%s` | `%s` | `%s` | %s |%n",
                            imp.function, imp.library, imp.mitreTechnique, imp.threatCategory);
                }
                out.println();
            }

            if (!d.iocFindings.isEmpty()) {
                out.println("## Extracted Indicators of Compromise (IOCs)");
                out.println();
                out.println("| Type | Address | Value |");
                out.println("|---|---|---|");
                for (ReportModel.IocFinding ioc : d.iocFindings) {
                    out.printf("| %s | `%s` | `%s` |%n", ioc.type, ioc.address, ioc.value);
                }
                out.println();
            }

            out.println("## Prioritized Functions & Disassembly Excerpts");
            out.println();
            int fLimit = Math.min(10, d.prioritizedFunctions.size());
            for (int i = 0; i < fLimit; i++) {
                ReportModel.FunctionScore fs = d.prioritizedFunctions.get(i);
                out.printf("### %d. `%s` @ `%s` (Threat Score: %d)%n",
                        i + 1, fs.function.getName(), fs.function.getEntryPoint(), fs.score);
                out.printf("- In-bound references: `%d` | Function calls: `%d` | Instructions: `%d`%n",
                        fs.refCount, fs.callCount, fs.instructionCount);
                if (fs.decompiledCode != null) {
                    out.println();
                    out.println("```c");
                    out.println(fs.decompiledCode.trim());
                    out.println("```");
                }
                out.println();
            }
        }
    }
}
