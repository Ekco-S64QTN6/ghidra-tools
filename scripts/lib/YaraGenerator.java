package lib;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Generates ready-to-use YARA detection rules (.yar) based on extracted
 * IOCs, high-signal strings, opcode byte patterns, and binary metadata.
 */
public class YaraGenerator {

    public static void generateRule(
            File outputFile,
            String binaryName,
            String md5,
            String sha256,
            String imphash,
            int threatScore,
            long fileSize,
            List<String> iocs,
            List<String> hexSignatures) throws IOException {

        outputFile.getParentFile().mkdirs();
        String ruleName = "rule_" + binaryName.replaceAll("[^a-zA-Z0-9_]", "_");
        if (!ruleName.matches("^[a-zA-Z_].*")) {
            ruleName = "rule_" + ruleName;
        }

        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8))) {
            out.println("/*");
            out.println("   Auto-generated YARA detection rule created by ghidra-report");
            out.println("   Binary:       " + binaryName);
            out.println("   Generated:    " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z").format(new Date()));
            out.println("   Threat Score: " + threatScore + "/100");
            out.println("*/");
            out.println();

            boolean isPe = (imphash != null && !imphash.isEmpty());
            if (isPe) {
                out.println("import \"pe\"");
                out.println();
            }

            out.println("rule " + ruleName + " {");
            out.println("    meta:");
            out.println("        description = \"Detection rule for " + binaryName + "\"");
            out.println("        author = \"ghidra-report\"");
            out.println("        date = \"" + new SimpleDateFormat("yyyy-MM-dd").format(new Date()) + "\"");
            out.println("        md5 = \"" + md5 + "\"");
            out.println("        sha256 = \"" + sha256 + "\"");
            if (isPe) {
                out.println("        imphash = \"" + imphash + "\"");
            }
            out.println("        threat_score = " + threatScore);
            out.println();

            out.println("    strings:");
            int strIdx = 1;
            Set<String> seenStrings = new HashSet<>();

            // Add IOC strings
            if (iocs != null) {
                for (String ioc : iocs) {
                    if (strIdx > 20) break;
                    String clean = ioc.replace("\\", "\\\\").replace("\"", "\\\"");
                    if (clean.length() >= 4 && seenStrings.add(clean)) {
                        out.println("        $s" + strIdx + " = \"" + clean + "\" ascii wide");
                        strIdx++;
                    }
                }
            }

            // Add hex signatures from top function opcodes
            int hexIdx = 1;
            if (hexSignatures != null) {
                for (String hex : hexSignatures) {
                    if (hexIdx > 5) break;
                    if (hex != null && hex.trim().length() >= 16) {
                        out.println("        $hex" + hexIdx + " = { " + hex.trim() + " }");
                        hexIdx++;
                    }
                }
            }

            if (strIdx == 1 && hexIdx == 1) {
                out.println("        $placeholder = \"" + binaryName + "\" ascii wide");
            }
            out.println();

            out.println("    condition:");
            if (isPe) {
                out.println("        uint16(0) == 0x5a4d and");
                out.println("        (");
                out.println("            pe.imphash() == \"" + imphash + "\"");
                if (hexIdx > 1) {
                    out.println("            or any of ($hex*)");
                }
                if (strIdx > 1) {
                    out.println("            or (filesize < " + Math.max(fileSize * 2, 1048576) + " and 1 of ($s*))");
                }
                if (strIdx == 1 && hexIdx == 1) {
                    out.println("            or $placeholder");
                }
                out.println("        )");
            } else {
                out.println("        filesize < " + Math.max(fileSize * 2, 1048576) + " and (");
                List<String> condParts = new ArrayList<>();
                if (hexIdx > 1) condParts.add("any of ($hex*)");
                if (strIdx > 1) condParts.add("1 of ($s*)");
                if (condParts.isEmpty()) condParts.add("$placeholder");
                out.println("            " + String.join(" or ", condParts));
                out.println("        )");
            }
            out.println("}");
        }
    }
}
