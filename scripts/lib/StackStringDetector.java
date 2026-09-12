package lib;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;

import java.util.ArrayList;
import java.util.List;

/**
 * Reconstructs obfuscated strings assembled char-by-char on the stack via
 * sequential immediate MOV instructions.
 */
public class StackStringDetector {

    public static class StackString {
        public final String value;
        public final String address;
        public final String functionName;
        public final int byteCount;

        public StackString(String value, String address, String functionName, int byteCount) {
            this.value = value;
            this.address = address;
            this.functionName = functionName;
            this.byteCount = byteCount;
        }
    }

    public static List<StackString> scanFunction(Function func, Listing listing) {
        List<StackString> results = new ArrayList<>();
        if (func == null || func.getBody().isEmpty()) return results;

        InstructionIterator instrs = listing.getInstructions(func.getBody(), true);
        StringBuilder currentStr = new StringBuilder();
        String startAddr = null;

        while (instrs.hasNext()) {
            Instruction ins = instrs.next();
            String mnem = ins.getMnemonicString().toUpperCase();

            // Look for move instructions: MOV, MOVB, MOVW, MOVD, STR, STRB
            boolean isMove = mnem.startsWith("MOV") || mnem.startsWith("STR");
            boolean charFound = false;

            if (isMove && ins.getNumOperands() >= 2) {
                // Check if operand 1 is an immediate scalar
                Object[] opObjs = ins.getOpObjects(1);
                for (Object o : opObjs) {
                    if (o instanceof Scalar) {
                        long val = ((Scalar) o).getUnsignedValue();
                        // Check if it represents 1, 2, or 4 printable ASCII characters
                        if (isPrintableAscii((int) (val & 0xFF))) {
                            char c1 = (char) (val & 0xFF);
                            if (startAddr == null) startAddr = ins.getAddress().toString();
                            currentStr.append(c1);

                            // Check byte 2
                            long b2 = (val >> 8) & 0xFF;
                            if (b2 != 0 && isPrintableAscii((int) b2)) {
                                currentStr.append((char) b2);
                                long b3 = (val >> 16) & 0xFF;
                                long b4 = (val >> 24) & 0xFF;
                                if (b3 != 0 && isPrintableAscii((int) b3)) {
                                    currentStr.append((char) b3);
                                    if (b4 != 0 && isPrintableAscii((int) b4)) {
                                        currentStr.append((char) b4);
                                    }
                                }
                            }
                            charFound = true;
                            break;
                        }
                    }
                }
            }

            if (!charFound) {
                // End of consecutive stack move sequence
                if (currentStr.length() >= 4) {
                    results.add(new StackString(currentStr.toString(), startAddr, func.getName(), currentStr.length()));
                }
                currentStr.setLength(0);
                startAddr = null;
            }
        }

        if (currentStr.length() >= 4) {
            results.add(new StackString(currentStr.toString(), startAddr, func.getName(), currentStr.length()));
        }

        return results;
    }

    private static boolean isPrintableAscii(int b) {
        return b >= 32 && b <= 126;
    }
}
