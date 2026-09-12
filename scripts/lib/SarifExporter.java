package lib;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Exports analysis findings in OASIS SARIF v2.1.0 format,
 * enabling integration with GitHub Code Scanning, Azure DevOps, and CI/CD pipelines.
 */
public class SarifExporter {

    public static class Finding {
        public String ruleId;
        public String category;
        public String message;
        public String address;
        public String level; // "error", "warning", "note"

        public Finding(String ruleId, String category, String message, String address, String level) {
            this.ruleId = ruleId;
            this.category = category;
            this.message = message;
            this.address = address;
            this.level = level;
        }
    }

    public static void exportSarif(
            File outputFile,
            String binaryName,
            List<Finding> findings) throws IOException {

        outputFile.getParentFile().mkdirs();

        // Unique rules
        Map<String, String> rulesMap = new LinkedHashMap<>();
        for (Finding f : findings) {
            if (!rulesMap.containsKey(f.ruleId)) {
                rulesMap.put(f.ruleId, f.category);
            }
        }

        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8))) {
            out.println("{");
            out.println("  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",");
            out.println("  \"version\": \"2.1.0\",");
            out.println("  \"runs\": [");
            out.println("    {");
            out.println("      \"tool\": {");
            out.println("        \"driver\": {");
            out.println("          \"name\": \"ghidra-report\",");
            out.println("          \"version\": \"0.2.0\",");
            out.println("          \"informationUri\": \"https://github.com/ghidra-tools\",");
            out.println("          \"rules\": [");

            int rIdx = 0;
            for (Map.Entry<String, String> entry : rulesMap.entrySet()) {
                out.println("            {");
                out.println("              \"id\": \"" + escapeJson(entry.getKey()) + "\",");
                out.println("              \"name\": \"" + escapeJson(entry.getKey().replace(".", "_")) + "\",");
                out.println("              \"shortDescription\": { \"text\": \"" + escapeJson(entry.getValue()) + "\" },");
                if (entry.getKey().startsWith("T")) {
                    out.println("              \"helpUri\": \"https://attack.mitre.org/techniques/" + escapeJson(entry.getKey().replace(".", "/")) + "/\"");
                } else {
                    out.println("              \"helpUri\": \"https://github.com/ghidra-tools\"");
                }
                out.print("            }");
                if (rIdx < rulesMap.size() - 1) out.println(",");
                else out.println();
                rIdx++;
            }

            out.println("          ]");
            out.println("        }");
            out.println("      },");

            // Results array
            out.println("      \"results\": [");
            for (int i = 0; i < findings.size(); i++) {
                Finding f = findings.get(i);
                out.println("        {");
                out.println("          \"ruleId\": \"" + escapeJson(f.ruleId) + "\",");
                out.println("          \"level\": \"" + escapeJson(f.level) + "\",");
                out.println("          \"message\": { \"text\": \"" + escapeJson(f.message) + "\" },");
                out.println("          \"locations\": [");
                out.println("            {");
                out.println("              \"physicalLocation\": {");
                out.println("                \"artifactLocation\": { \"uri\": \"" + escapeJson(binaryName) + "\" },");
                out.println("                \"region\": {");
                out.println("                  \"message\": { \"text\": \"Offset/Address: " + escapeJson(f.address != null ? f.address : "N/A") + "\" }");
                out.println("                }");
                out.println("              }");
                out.println("            }");
                out.println("          ]");
                out.print("        }");
                if (i < findings.size() - 1) out.println(",");
                else out.println();
            }
            out.println("      ]");
            out.println("    }");
            out.println("  ]");
            out.println("}");
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
