package lib;

/** Escaping helpers shared by the JSON and HTML renderers. */
public class ReportFormat {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * Escape a Java string for inclusion between JSON quotes.
     *
     * Every JSON control character below U+0020 is escaped. Common controls use
     * their short JSON spellings; the remaining controls use \u00xx escapes.
     */
    public static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder escaped = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        escaped.append("\\u00")
                                .append(HEX[(c >>> 4) & 0x0f])
                                .append(HEX[c & 0x0f]);
                    } else {
                        escaped.append(c);
                    }
            }
        }
        return escaped.toString();
    }

    public static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
