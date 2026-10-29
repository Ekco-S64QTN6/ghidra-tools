import lib.ReportFormat;

/** Prints the production JSON escaping helper output for a Python JSON parser. */
public final class ReportFormatEscapeProbe {
    public static void main(String[] args) {
        StringBuilder value = new StringBuilder();
        for (int c = 0; c < 0x20; c++) {
            value.append((char) c);
        }
        value.append(" Quote:\" Backslash:\\ Unicode:雪 Ω 😀 Markup:<script>&</script>");
        if (!"".equals(ReportFormat.escapeJson(null))) {
            throw new AssertionError("null values should retain the writer's empty-string behavior");
        }
        System.out.println("{\"value\":\"" + ReportFormat.escapeJson(value.toString()) + "\"}");
    }
}
