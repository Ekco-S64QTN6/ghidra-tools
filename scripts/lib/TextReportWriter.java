package lib;

import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

/** Renders the ASCII terminal report (.txt) from a populated {@link ReportModel.ReportData}. */
public class TextReportWriter {

    public static void write(File file, ReportModel.ReportData d) throws IOException {
        file.getParentFile().mkdirs();
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
            printBanner(out, d);
            printExecutiveSummary(out, d);
            printProgramInfo(out, d);
            printMemoryMap(out, d);
            printStackStrings(out, d);
            printDeobfuscatedStrings(out, d);
            if (d.isSnes) {
                if (d.snesHeader != null) {
                    SnesAnalyzer.printSnesReport(out, d.snesHeader, d.snesMmioAccesses, d.snesDmaChannels);
                }
                printSnesVectors(out, d);
            }
            printSuspiciousApis(out, d);
            printImportsSummary(out, d);
            printExports(out, d);
            printIocs(out, d);
            DisassemblyPrinter.printPriorityDisassembly(out, d.program, d.prioritizedFunctions, d.fullDisasm);
            DisassemblyPrinter.printDecompilerExcerpts(out, d.prioritizedFunctions);
            printStrings(out, d);
            printAnalysisQuality(out, d);
            out.println("════════════════════════════════════════════════════════════════════════════════");
            out.println("  END OF REPORT");
            out.println("════════════════════════════════════════════════════════════════════════════════");
        }
    }

    private static void printBanner(PrintWriter out, ReportModel.ReportData d) {
        String title = "GHIDRA ANALYSIS REPORT — " + d.formatLabel;
        final int INNER = 78;
        int totalPad = INNER - title.length();
        int left = Math.max(0, totalPad / 2);
        int right = Math.max(0, totalPad - left);
        String titleLine = (title.length() > INNER) ? title.substring(0, INNER - 3) + "..." : " ".repeat(left) + title + " ".repeat(right);

        out.println("╔" + "═".repeat(INNER) + "╗");
        out.println("║" + titleLine + "║");
        out.println("╚" + "═".repeat(INNER) + "╝");
        out.println();
        out.println("  File:      " + d.program.getName());
        out.println("  Format:    " + d.program.getExecutableFormat());
        out.println("  Generated: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z").format(new Date()));
        out.println();
    }

    /** Inner width of the triage box, matching the ─ runs in its borders. */
    private static final int BOX_WIDTH = 80;

    /** Writes one boxed row, truncating or padding so the right border always lines up. */
    private static void boxRow(PrintWriter out, String content) {
        if (content.length() > BOX_WIDTH) {
            content = content.substring(0, BOX_WIDTH - 3) + "...";
        }
        out.printf("│%-" + BOX_WIDTH + "s│%n", content);
    }

    private static void printExecutiveSummary(PrintWriter out, ReportModel.ReportData d) {
        out.println("┌─ THREAT TRIAGE SUMMARY " + "─".repeat(BOX_WIDTH - 24) + "┐");
        boxRow(out, String.format("  Risk Score:  %-3d / 100  [%s]", d.riskScore, d.riskLevel));
        out.println("├" + "─".repeat(BOX_WIDTH) + "┤");
        if (d.threatIndicators.isEmpty()) {
            boxRow(out, "  ● No overt threat indicators detected. Benign or non-PE/ELF firmware sample.");
        } else {
            int shown = 0;
            for (HeuristicScorer.ThreatIndicator ti : d.threatIndicators) {
                if (shown >= 8) {
                    boxRow(out, String.format("  ... and %d additional indicator(s)", d.threatIndicators.size() - 8));
                    break;
                }
                boxRow(out, String.format("  ● [%s] %s%s",
                        ti.mitreId != null ? ti.mitreId : ti.category,
                        ti.description,
                        ti.weight > 0 ? " (+" + ti.weight + ")" : ""));
                shown++;
            }
        }
        out.println("└" + "─".repeat(BOX_WIDTH) + "┘");
        out.println();
    }

    private static void printProgramInfo(PrintWriter out, ReportModel.ReportData d) {
        Program p = d.program;
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  PROGRAM INFORMATION");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        out.printf("  Name:           %s%n", p.getName());
        out.printf("  Language:       %s%n", p.getLanguage().getLanguageDescription().getDescription());
        out.printf("  Language ID:    %s%n", p.getLanguageID());
        out.printf("  Compiler Spec:  %s%n", p.getCompilerSpec().getCompilerSpecID());
        out.printf("  Endianness:     %s%n", p.getLanguage().isBigEndian() ? "Big Endian" : "Little Endian");
        out.printf("  Address Size:   %d bits%n", p.getDefaultPointerSize() * 8);
        out.printf("  Executable Fmt: %s%n", p.getExecutableFormat());
        out.printf("  Executable MD5: %s%n", p.getExecutableMD5());
        out.printf("  Executable SHA: %s%n", p.getExecutableSHA256());
        if (d.imphash != null) out.printf("  PE Imphash:     %s%n", d.imphash);
        out.printf("  Created:        %s%n", p.getCreationDate());

        Options infoList = p.getOptions("Program Information");
        for (String name : infoList.getOptionNames()) {
            try {
                Object val = infoList.getObject(name, null);
                if (val != null) {
                    out.printf("  [Info] %-30s = %s%n", name, val.toString());
                }
            } catch (Exception ignored) {}
        }
        out.println();
    }

    private static void printMemoryMap(PrintWriter out, ReportModel.ReportData d) {
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  MEMORY MAP & SHANNON ENTROPY");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        out.printf("  %-16s %-12s %-12s %9s  %-5s  %-6s  %-10s  %s%n",
                "Block Name", "Start", "End", "Size", "Perms", "Entropy", "Status", "Packer / Notes");
        out.println("  " + "-".repeat(95));

        for (ReportModel.BlockInfo b : d.memoryBlocks) {
            String entropyStr = String.format("%.2f", b.entropy);
            String status = b.isHighEntropy ? "PACKED/CRYPT" : (b.entropy > 6.0 ? "MODERATE" : "NORMAL");
            String note = b.packerHint.isEmpty() ? (b.isRwx ? "RWX ALERT" : "") : b.packerHint;
            out.printf("  %-16s %-12s %-12s %9d  %-5s  %-6s  %-10s  %s%n",
                    b.name, b.start, b.end, b.size, b.perms, entropyStr, status, note);
        }
        out.println("  " + "-".repeat(95));
        out.printf("  Total mapped memory: %,d bytes (%,.1f KB)%n", d.totalInitializedBytes, d.totalInitializedBytes / 1024.0);
        out.println();
    }

    private static void printStackStrings(PrintWriter out, ReportModel.ReportData d) {
        if (d.stackStrings.isEmpty()) return;
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  RECONSTRUCTED STACK STRINGS (OBFUSCATION EVASION)");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        out.printf("  %-16s %-16s %s%n", "Address", "Function", "Reconstructed String");
        out.println("  " + "-".repeat(75));
        for (StackStringDetector.StackString ss : d.stackStrings) {
            out.printf("  %-16s %-16s \"%s\"%n", ss.address, ss.functionName, ss.value);
        }
        out.println("  " + "-".repeat(75));
        out.println();
    }

    private static void printDeobfuscatedStrings(PrintWriter out, ReportModel.ReportData d) {
        if (d.deobfuscatedStrings.isEmpty()) return;
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  DEOBFUSCATED STRINGS & EMULATION RECOVERY");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        out.printf("  %-16s %-18s %-22s %s%n", "Address", "Function", "Method", "Decrypted String");
        out.println("  " + "-".repeat(80));
        for (EmulatorDeobfuscator.DeobfuscatedString ds : d.deobfuscatedStrings) {
            out.printf("  %-16s %-18s %-22s \"%s\"%n", ds.address, ds.functionName, ds.method, ds.value);
        }
        out.println("  " + "-".repeat(80));
        out.println();
    }

    private static void printSnesVectors(PrintWriter out, ReportModel.ReportData d) {
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  SNES INTERRUPT VECTORS");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        String[][] nativeVectors = {
                {"00ffe4", "COP"}, {"00ffe6", "BRK"}, {"00ffe8", "ABORT"},
                {"00ffea", "NMI (VBlank)"}, {"00ffec", "RESET"}, {"00ffee", "IRQ"}
        };
        Memory mem = d.program.getMemory();
        AddressSpace space = d.program.getAddressFactory().getDefaultAddressSpace();
        SymbolTable st = d.program.getSymbolTable();
        out.println("  Native Mode (65816) Vectors:");
        out.printf("  %-14s %-20s %-14s %s%n", "Vector Addr", "Vector Name", "Target", "Label");
        out.println("  " + "-".repeat(70));
        for (String[] vec : nativeVectors) {
            try {
                Address a = space.getAddress(vec[0]);
                int low = mem.getByte(a) & 0xFF;
                int high = mem.getByte(a.add(1)) & 0xFF;
                int target = (high << 8) | low;
                Address targetAddress = space.getAddress(String.format("00%04x", target));
                Symbol sym = st.getPrimarySymbol(targetAddress);
                String label = (sym != null) ? sym.getName() : "(none)";
                out.printf("  %-14s %-20s $%04X         %s%n", vec[0], vec[1], target, label);
            } catch (Exception e) {
                out.printf("  %-14s %-20s (unreadable)%n", vec[0], vec[1]);
            }
        }
        out.println();
    }

    private static void printSuspiciousApis(PrintWriter out, ReportModel.ReportData d) {
        if (d.suspiciousImports.isEmpty()) return;
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  SUSPICIOUS APIS & MITRE ATT&CK TECHNIQUES");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        out.printf("  %-28s %-16s %-14s %s%n", "Function", "Library", "ATT&CK ID", "Category");
        out.println("  " + "-".repeat(85));
        for (ReportModel.ImportEntry imp : d.suspiciousImports) {
            out.printf("  %-28s %-16s %-14s %s%n",
                    imp.function, imp.library, imp.mitreTechnique, imp.threatCategory);
        }
        out.println();
    }

    private static void printImportsSummary(PrintWriter out, ReportModel.ReportData d) {
        if (d.importsByLib.isEmpty()) return;
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  IMPORTED LIBRARIES & FUNCTIONS");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        for (Map.Entry<String, List<ReportModel.ImportEntry>> entry : d.importsByLib.entrySet()) {
            out.printf("  [%s] — %d imports%n", entry.getKey(), entry.getValue().size());
            int shown = 0;
            for (ReportModel.ImportEntry imp : entry.getValue()) {
                if (shown >= 20) {
                    out.printf("    ... (%d more)%n", entry.getValue().size() - 20);
                    break;
                }
                out.printf("    %-35s %s%n", imp.function, imp.mitreTechnique != null ? "[" + imp.mitreTechnique + "]" : "");
                shown++;
            }
            out.println();
        }
    }

    private static void printExports(PrintWriter out, ReportModel.ReportData d) {
        if (d.exportsList.isEmpty()) return;
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  EXPORTS & EXTERNAL ENTRY POINTS");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        for (ReportModel.ExportEntry exp : d.exportsList) {
            out.printf("  %-16s  %s%n", exp.address, exp.name);
        }
        out.println();
    }

    private static void printIocs(PrintWriter out, ReportModel.ReportData d) {
        if (d.iocFindings.isEmpty()) return;
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  EXTRACTED INDICATORS OF COMPROMISE (IOCS)");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        out.printf("  %-14s %-22s %s%n", "Address", "Type", "Indicator Value");
        out.println("  " + "-".repeat(85));
        for (ReportModel.IocFinding ioc : d.iocFindings) {
            out.printf("  %-14s %-22s %s%s%n",
                    ioc.address, ioc.type, ioc.value,
                    ioc.context.isEmpty() ? "" : " (" + ioc.context + ")");
        }
        out.println();
    }

    private static void printStrings(PrintWriter out, ReportModel.ReportData d) {
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  DEFINED STRINGS EXCERPT");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        int shown = 0;
        for (String s : d.definedStringsList) {
            if (shown >= 80) {
                out.printf("  ... (%d more strings defined)%n", d.definedStringsList.size() - 80);
                break;
            }
            out.println("  " + s);
            shown++;
        }
        out.println();
    }

    private static void printAnalysisQuality(PrintWriter out, ReportModel.ReportData d) {
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  ANALYSIS QUALITY INDICATORS");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        out.printf("  Functions identified:       %,d%n", d.prioritizedFunctions.size());
        out.printf("  Defined symbols:            %,d%n", d.program.getSymbolTable().getNumSymbols());
        out.printf("  Initialized memory:         %,d bytes%n", d.totalInitializedBytes);
        out.printf("  Disassembled code:          %,d bytes%n", d.totalDisassembledBytes);
        out.printf("  Estimated code coverage:    %.1f%%%n", d.codeCoverage);
        out.println();
    }
}
