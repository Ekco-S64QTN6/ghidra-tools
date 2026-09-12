package lib;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.List;

/**
 * DecompInterface wrapper. Decompiles the highest-scoring functions into C pseudocode,
 * bounded by both a function count and a per-function timeout so a single pathological
 * function can never stall a headless run.
 */
public class DecompilerExporter {

    public static final int DEFAULT_LIMIT = 5;
    public static final int DEFAULT_TIMEOUT_SECONDS = 30;

    /**
     * Decompiles up to {@code limit} functions from the head of {@code prioritized},
     * storing the result on each {@link ReportModel.FunctionScore#decompiledCode}.
     *
     * @return the number of functions that produced pseudocode.
     */
    public static int decompileTop(Program program,
                                   List<ReportModel.FunctionScore> prioritized,
                                   int limit,
                                   int timeoutSeconds,
                                   TaskMonitor monitor) {
        if (program == null || prioritized == null || prioritized.isEmpty() || limit <= 0) {
            return 0;
        }

        int succeeded = 0;
        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(program)) {
                return 0;
            }
            int attempted = 0;
            for (ReportModel.FunctionScore fs : prioritized) {
                if (attempted >= limit) break;
                attempted++;
                if (fs.function == null) continue;
                try {
                    DecompileResults res = decomp.decompileFunction(fs.function, timeoutSeconds, monitor);
                    if (res != null && res.decompileCompleted()) {
                        DecompiledFunction df = res.getDecompiledFunction();
                        if (df != null && df.getC() != null) {
                            fs.decompiledCode = df.getC();
                            succeeded++;
                        }
                    }
                } catch (Exception e) {
                    fs.decompiledCode = "// Decompilation failed: " + e.getMessage();
                }
            }
        } finally {
            decomp.dispose();
        }
        return succeeded;
    }

    public static int decompileTop(Program program,
                                   List<ReportModel.FunctionScore> prioritized,
                                   TaskMonitor monitor) {
        return decompileTop(program, prioritized, DEFAULT_LIMIT, DEFAULT_TIMEOUT_SECONDS, monitor);
    }
}
