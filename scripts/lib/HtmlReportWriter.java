package lib;

import ghidra.program.model.listing.Program;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import static lib.ReportFormat.escapeHtml;

/** Renders the self-contained dark-mode HTML report (.html). No external assets. */
public class HtmlReportWriter {

    public static void write(File file, ReportModel.ReportData d) throws IOException {
        file.getParentFile().mkdirs();
        Program p = d.program;
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
            out.println("<!DOCTYPE html>");
            out.println("<html lang=\"en\">");
            out.println("<head>");
            out.println("  <meta charset=\"UTF-8\">");
            out.println("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            out.println("  <title>Ghidra Report — " + escapeHtml(p.getName()) + "</title>");
            printStyles(out);
            out.println("</head>");
            out.println("<body>");
            out.println("<div class=\"container\">");
            out.println("  <header>");
            out.println("    <h1>" + escapeHtml(p.getName()) + "</h1>");
            out.println("    <div>");
            out.println("      <span class=\"badge " + (d.riskScore >= 60 ? "badge-crit" : (d.riskScore >= 30 ? "badge-high" : "badge-low")) + "\">RISK: " + d.riskScore + "/100 (" + escapeHtml(d.riskLevel) + ")</span>");
            out.println("      <span class=\"badge\" style=\"background:#30363d; color:#c9d1d9;\">" + escapeHtml(d.formatLabel) + "</span>");
            out.println("      <span style=\"color:#8b949e; font-size:12px;\">MD5: " + escapeHtml(p.getExecutableMD5()) + "</span>");
            out.println("    </div>");
            out.println("  </header>");

            out.println("  <div class=\"card\">");
            out.println("    <h2 style=\"margin-top:0; color:#fff; font-size:16px;\">Threat Triage Indicators</h2>");
            if (d.threatIndicators.isEmpty()) {
                out.println("    <p style=\"color:#8b949e;\">No overt threats detected.</p>");
            } else {
                out.println("    <ul>");
                for (HeuristicScorer.ThreatIndicator ti : d.threatIndicators) {
                    out.println("      <li><strong>[" + escapeHtml(ti.mitreId != null ? ti.mitreId : ti.category) + "]</strong> " + escapeHtml(ti.description) + "</li>");
                }
                out.println("    </ul>");
            }
            out.println("  </div>");

            out.println("  <div class=\"card\">");
            out.println("    <h2 style=\"margin-top:0; color:#fff; font-size:16px;\">Memory Map &amp; Shannon Entropy</h2>");
            out.println("    <table>");
            out.println("      <tr><th>Block</th><th>Start</th><th>End</th><th>Size</th><th>Perms</th><th>Entropy</th><th>Status</th><th>Notes</th></tr>");
            for (ReportModel.BlockInfo b : d.memoryBlocks) {
                String color = b.isHighEntropy ? "color:var(--danger);font-weight:bold;" : "";
                out.println("      <tr style=\"" + color + "\"><td>" + escapeHtml(b.name) + "</td><td>" + escapeHtml(b.start) + "</td><td>" + escapeHtml(b.end) + "</td><td>" + b.size + "</td><td>" + escapeHtml(b.perms) + "</td><td>" + String.format("%.2f", b.entropy) + "</td><td>" + (b.isHighEntropy ? "PACKED/CRYPT" : "Normal") + "</td><td>" + escapeHtml(b.packerHint.isEmpty() ? (b.isRwx ? "RWX ALERT" : "") : b.packerHint) + "</td></tr>");
            }
            out.println("    </table>");
            out.println("  </div>");

            if (!d.suspiciousImports.isEmpty()) {
                out.println("  <div class=\"card\">");
                out.println("    <h2 style=\"margin-top:0; color:#fff; font-size:16px;\">Suspicious APIs (ATT&amp;CK Tagged)</h2>");
                out.println("    <table>");
                out.println("      <tr><th>Function</th><th>Library</th><th>Technique</th><th>Category</th></tr>");
                for (ReportModel.ImportEntry imp : d.suspiciousImports) {
                    out.println("      <tr><td><code>" + escapeHtml(imp.function) + "</code></td><td>" + escapeHtml(imp.library) + "</td><td><span class=\"badge badge-high\">" + escapeHtml(imp.mitreTechnique) + "</span></td><td>" + escapeHtml(imp.threatCategory) + "</td></tr>");
                }
                out.println("    </table>");
                out.println("  </div>");
            }

            if (!d.iocFindings.isEmpty()) {
                out.println("  <div class=\"card\">");
                out.println("    <h2 style=\"margin-top:0; color:#fff; font-size:16px;\">Extracted IOCs</h2>");
                out.println("    <table>");
                out.println("      <tr><th>Type</th><th>Address</th><th>Value</th></tr>");
                for (ReportModel.IocFinding ioc : d.iocFindings) {
                    out.println("      <tr><td>" + escapeHtml(ioc.type) + "</td><td><code>" + escapeHtml(ioc.address) + "</code></td><td><code>" + escapeHtml(ioc.value) + "</code></td></tr>");
                }
                out.println("    </table>");
                out.println("  </div>");
            }

            out.println("  <div class=\"card\">");
            out.println("    <h2 style=\"margin-top:0; color:#fff; font-size:16px;\">Top Decompiled Pseudocode</h2>");
            int fCount = 0;
            for (ReportModel.FunctionScore fs : d.prioritizedFunctions) {
                if (fCount >= 3) break;
                if (fs.decompiledCode != null) {
                    out.println("    <h3 style=\"font-size:14px; color:#58a6ff;\">" + escapeHtml(fs.function.getName()) + " @ " + escapeHtml(fs.function.getEntryPoint().toString()) + " (Score: " + fs.score + ")</h3>");
                    out.println("    <pre><code>" + escapeHtml(fs.decompiledCode.trim()) + "</code></pre>");
                    fCount++;
                }
            }
            out.println("  </div>");

            out.println("</div>");
            out.println("</body>");
            out.println("</html>");
        }
    }

    private static void printStyles(PrintWriter out) {
        out.println("  <style>");
        out.println("    :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --danger: #f85149; --warn: #d29922; --success: #3fb950; }");
        out.println("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; line-height: 1.5; }");
        out.println("    .container { max-width: 1200px; margin: 0 auto; }");
        out.println("    header { border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }");
        out.println("    h1 { margin: 0 0 8px 0; color: #fff; font-size: 24px; }");
        out.println("    .badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; margin-right: 8px; }");
        out.println("    .badge-crit { background: #b62324; color: #fff; }");
        out.println("    .badge-high { background: #d29922; color: #000; }");
        out.println("    .badge-low { background: #238636; color: #fff; }");
        out.println("    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }");
        out.println("    table { width: 100%; border-collapse: collapse; margin-top: 12px; }");
        out.println("    th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }");
        out.println("    th { background: #21262d; color: #8b949e; }");
        out.println("    pre { background: #0b0e14; border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; font-family: monospace; font-size: 12px; color: #79c0ff; }");
        out.println("    code { font-family: monospace; background: #21262d; padding: 2px 4px; border-radius: 4px; font-size: 12px; }");
        out.println("  </style>");
    }
}
