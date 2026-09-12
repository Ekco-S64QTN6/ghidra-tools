package lib;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts and classifies IOCs, high-signal strings, network indicators,
 * registry paths, and decoded payloads.
 */
public class IocExtractor {

    public static class IocFinding {
        public String type;
        public String value;
        public String address;
        public String context;

        public IocFinding(String type, String value, String address, String context) {
            this.type = type;
            this.value = value;
            this.address = address;
            this.context = context;
        }
    }

    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?!127\\.|10\\.|192\\.168\\.|172\\.(?:1[6-9]|2[0-9]|3[0-1])\\.|0\\.|255\\.)" +
            "((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
            "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");

    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[a-zA-Z0-9.\\-_]+(?::\\d+)?(?:/[^\\s\"]*)?");

    private static final Pattern REG_PATTERN = Pattern.compile(
            "(?i)(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|Software\\\\Microsoft\\\\[a-zA-Z0-9_\\\\]+)");

    private static final Pattern PATH_PATTERN = Pattern.compile(
            "(?i)(?:[a-zA-Z]:\\\\(?:Windows|System32|Users|ProgramData|Temp)\\\\[^\"\\s<>|]+|/(?:etc|tmp|var|usr/bin)/[^\"\\s]+|%APPDATA%|%TEMP%)");

    private static final Pattern B64_PATTERN = Pattern.compile(
            "[A-Za-z0-9+/]{24,}={0,2}");

    private static final Pattern HEX_PATTERN = Pattern.compile(
            "\\b[0-9a-fA-F]{16,}\\b");

    public static List<IocFinding> scanString(String str, String address) {
        List<IocFinding> findings = new ArrayList<>();
        if (str == null || str.trim().isEmpty()) return findings;

        // 1. IPv4 match
        Matcher mIp = IP_PATTERN.matcher(str);
        while (mIp.find()) {
            findings.add(new IocFinding("IPv4 Address", mIp.group(), address, "Network IOC"));
        }

        // 2. URL match
        Matcher mUrl = URL_PATTERN.matcher(str);
        while (mUrl.find()) {
            findings.add(new IocFinding("URL", mUrl.group(), address, "Web Endpoint"));
        }

        // 3. Registry match
        Matcher mReg = REG_PATTERN.matcher(str);
        while (mReg.find()) {
            findings.add(new IocFinding("Registry Key", mReg.group(), address, "Persistence / Config"));
        }

        // 4. File path match
        Matcher mPath = PATH_PATTERN.matcher(str);
        while (mPath.find()) {
            findings.add(new IocFinding("System Path", mPath.group(), address, "Filesystem Reference"));
        }

        // 5. Base64 encoded payload match
        Matcher mB64 = B64_PATTERN.matcher(str);
        while (mB64.find()) {
            String match = mB64.group();
            try {
                byte[] decoded = Base64.getDecoder().decode(match);
                int printable = 0;
                for (byte b : decoded) {
                    if ((b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9) printable++;
                }
                if (decoded.length > 8 && (double) printable / decoded.length > 0.75) {
                    String clean = new String(decoded, StandardCharsets.UTF_8).replaceAll("[^\\x20-\\x7E]", ".");
                    findings.add(new IocFinding("Base64 Decoded String", clean, address, "Encoded: " + match));
                }
            } catch (Exception ignored) {}
        }

        // 6. Hex-encoded ASCII payload match
        Matcher mHex = HEX_PATTERN.matcher(str);
        while (mHex.find()) {
            String match = mHex.group();
            if (match.length() % 2 == 0) {
                try {
                    byte[] bytes = new byte[match.length() / 2];
                    boolean validHex = true;
                    for (int i = 0; i < match.length(); i += 2) {
                        bytes[i / 2] = (byte) Integer.parseInt(match.substring(i, i + 2), 16);
                    }
                    int printable = 0;
                    for (byte b : bytes) {
                        if ((b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9) printable++;
                    }
                    if (bytes.length >= 8 && (double) printable / bytes.length > 0.75) {
                        String clean = new String(bytes, StandardCharsets.UTF_8).replaceAll("[^\\x20-\\x7E]", ".");
                        findings.add(new IocFinding("Hex Decoded String", clean, address, "Hex: " + match));
                    }
                } catch (Exception ignored) {}
            }
        }

        return findings;
    }

    public static String classifyString(String s) {
        if (s == null) return "General";
        if (URL_PATTERN.matcher(s).find()) return "Network URL";
        if (IP_PATTERN.matcher(s).find()) return "Network IP";
        if (REG_PATTERN.matcher(s).find()) return "Registry Key";
        if (PATH_PATTERN.matcher(s).find()) return "File Path";
        if (s.contains("%s") || s.contains("%d") || s.contains("%x") || s.contains("%02x")) return "Format String";
        if (s.length() > 30 && B64_PATTERN.matcher(s).find()) return "Encoded Blob";
        return "UI / Text";
    }
}
