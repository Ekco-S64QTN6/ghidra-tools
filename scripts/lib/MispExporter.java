package lib;

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

/**
 * Exports threat findings in standard MISP (Malware Information Sharing Platform)
 * event JSON format for threat intelligence platforms, OpenCTI, and SOAR ingestion.
 */
public class MispExporter {

    public static class MispAttribute {
        public final String category;
        public final String type;
        public final String value;
        public final String comment;
        public final boolean toIds;

        public MispAttribute(String category, String type, String value, String comment, boolean toIds) {
            this.category = category;
            this.type = type;
            this.value = value;
            this.comment = comment;
            this.toIds = toIds;
        }
    }

    public static void exportMisp(
            File outputFile,
            String binaryName,
            String md5,
            String sha256,
            String imphash,
            int threatScore,
            String riskLevel,
            List<IocExtractor.IocFinding> iocs,
            List<ApiTagger.ApiTag> suspiciousApis) throws IOException {

        outputFile.getParentFile().mkdirs();
        String dateStr = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

        String threatLevelId = "4";
        if ("CRITICAL".equalsIgnoreCase(riskLevel) || "HIGH".equalsIgnoreCase(riskLevel)) {
            threatLevelId = "1";
        } else if ("MEDIUM".equalsIgnoreCase(riskLevel)) {
            threatLevelId = "2";
        } else if ("LOW".equalsIgnoreCase(riskLevel)) {
            threatLevelId = "3";
        }

        List<MispAttribute> attrs = new ArrayList<>();

        if (md5 != null && !md5.isEmpty()) {
            attrs.add(new MispAttribute("Payload delivery", "filename|md5", binaryName + "|" + md5, "Binary MD5 hash", true));
        }
        if (sha256 != null && !sha256.isEmpty()) {
            attrs.add(new MispAttribute("Payload delivery", "filename|sha256", binaryName + "|" + sha256, "Binary SHA256 hash", true));
        }
        if (imphash != null && !imphash.isEmpty()) {
            attrs.add(new MispAttribute("Payload delivery", "imphash", imphash, "PE Import Hash", true));
        }

        if (iocs != null) {
            for (IocExtractor.IocFinding ioc : iocs) {
                if ("IPv4 Address".equals(ioc.type)) {
                    attrs.add(new MispAttribute("Network activity", "ip-dst", ioc.value, "Extracted IP indicator", true));
                } else if ("URL".equals(ioc.type)) {
                    attrs.add(new MispAttribute("Network activity", "url", ioc.value, "Extracted URL endpoint", true));
                } else if ("Registry Key".equals(ioc.type)) {
                    attrs.add(new MispAttribute("Artifacts dropped", "regkey", ioc.value, "Windows Registry persistence/config key", false));
                } else if ("System Path".equals(ioc.type)) {
                    attrs.add(new MispAttribute("Artifacts dropped", "filename", ioc.value, "Referenced filesystem path", false));
                }
            }
        }

        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8))) {
            out.println("{");
            out.println("  \"Event\": {");
            out.println("    \"info\": \"ghidra-report Threat Triage: " + escapeJson(binaryName) + " (Score: " + threatScore + "/100 [" + escapeJson(riskLevel) + "])\",");
            out.println("    \"date\": \"" + dateStr + "\",");
            out.println("    \"threat_level_id\": \"" + threatLevelId + "\",");
            out.println("    \"analysis\": \"2\",");
            out.println("    \"distribution\": \"0\",");
            out.println("    \"Attribute\": [");

            for (int i = 0; i < attrs.size(); i++) {
                MispAttribute a = attrs.get(i);
                out.println("      {");
                out.println("        \"category\": \"" + escapeJson(a.category) + "\",");
                out.println("        \"type\": \"" + escapeJson(a.type) + "\",");
                out.println("        \"value\": \"" + escapeJson(a.value) + "\",");
                out.println("        \"comment\": \"" + escapeJson(a.comment) + "\",");
                out.println("        \"to_ids\": " + a.toIds);
                if (i < attrs.size() - 1) {
                    out.println("      },");
                } else {
                    out.println("      }");
                }
            }

            out.println("    ]");
            out.println("  }");
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
