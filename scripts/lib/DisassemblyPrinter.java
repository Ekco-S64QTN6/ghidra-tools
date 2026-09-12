package lib;

import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import java.io.PrintWriter;
import java.util.List;

/**
 * Renders the prioritized disassembly and decompiler pseudocode sections of the
 * text report. Functions arrive pre-sorted by threat/complexity score.
 */
public class DisassemblyPrinter {

    private static final int DEFAULT_FUNCTION_LIMIT = 15;
    private static final int MAX_INSTRUCTIONS_PER_FUNCTION = 35;
    private static final int DECOMPILER_EXCERPT_LIMIT = 5;

    public static void printPriorityDisassembly(PrintWriter out,
                                                Program program,
                                                List<ReportModel.FunctionScore> prioritized,
                                                boolean fullDisasm) {
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.printf("  PRIORITIZED DISASSEMBLY (%s)%n",
                fullDisasm ? "All Functions" : "Top " + DEFAULT_FUNCTION_LIMIT + " Functions by Threat/Complexity Score");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();

        Listing listing = program.getListing();
        int limit = fullDisasm ? prioritized.size() : Math.min(DEFAULT_FUNCTION_LIMIT, prioritized.size());
        for (int idx = 0; idx < limit; idx++) {
            ReportModel.FunctionScore fs = prioritized.get(idx);
            Function f = fs.function;
            out.printf("  ┌─ #%d: %s @ %s [Score: %d | XRefs: %d | Calls: %d | Instr: %d] ───%n",
                    idx + 1, f.getName(), f.getEntryPoint().toString(), fs.score, fs.refCount, fs.callCount, fs.instructionCount);

            InstructionIterator instrs = listing.getInstructions(f.getBody(), true);
            int count = 0;
            while (instrs.hasNext() && count < MAX_INSTRUCTIONS_PER_FUNCTION) {
                Instruction instr = instrs.next();
                StringBuilder bytes = new StringBuilder();
                for (int i = 0; i < instr.getLength(); i++) {
                    try {
                        bytes.append(String.format("%02x ", instr.getByte(i) & 0xFF));
                    } catch (Exception e) {
                        bytes.append("?? ");
                    }
                }
                String comment = "";
                String eol = instr.getComment(CommentType.EOL);
                if (eol != null) comment = " ; " + eol;

                out.printf("  │ %-14s %-14s %-8s %-22s%s%n",
                        instr.getAddress().toString(),
                        bytes.toString().trim(),
                        instr.getMnemonicString(),
                        instr.getDefaultOperandRepresentation(0) + (instr.getNumOperands() > 1 ? ", " + instr.getDefaultOperandRepresentation(1) : ""),
                        comment);
                count++;
            }
            if (instrs.hasNext()) {
                out.println("  │ ... (truncated)");
            }
            out.println("  └─────────────────────────────────────────────────────────────────────────────");
            out.println();
        }
    }

    public static void printDecompilerExcerpts(PrintWriter out, List<ReportModel.FunctionScore> prioritized) {
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  DECOMPILER PSEUDOCODE (Top " + DECOMPILER_EXCERPT_LIMIT + " Priority Functions)");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        int count = 0;
        for (ReportModel.FunctionScore fs : prioritized) {
            if (count >= DECOMPILER_EXCERPT_LIMIT) break;
            if (fs.decompiledCode != null) {
                out.printf("  /* --- Function: %s @ %s (Score: %d) --- */%n",
                        fs.function.getName(), fs.function.getEntryPoint(), fs.score);
                for (String line : fs.decompiledCode.split("\n")) {
                    out.println("  " + line);
                }
                out.println();
                count++;
            }
        }
        if (count == 0) {
            out.println("  (No decompiled pseudocode available for this architecture / sample)");
            out.println();
        }
    }
}
