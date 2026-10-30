package lib;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.StackReference;

import java.util.ArrayList;
import java.util.List;

/**
 * Reconstructs strings written by consecutive immediate stores into one
 * contiguous stack-frame buffer.
 *
 * Unlike a mnemonic-only scan, a candidate must have:
 * - a Ghidra stack reference on a write operand;
 * - a P-code STORE whose stored value is a constant;
 * - a one-to-eight-byte store containing printable ASCII; and
 * - a stack offset contiguous with the previous store in instruction order.
 *
 * This intentionally favours precision over recovering values propagated
 * through registers or more complex data-flow sequences.
 */
public class StackStringDetector {

    private static final int MIN_STRING_BYTES = 4;
    private static final int MAX_STORE_BYTES = 8;
    private static final int MAX_STRING_BYTES = 128;

    public static class StackString {
        public final String value;
        public final String address;
        public final String functionName;
        public final int byteCount;
        public final int stackOffsetStart;
        public final int stackOffsetEnd;
        public final String method;
        public final String evidence;

        public StackString(
                String value,
                String address,
                String functionName,
                int byteCount,
                int stackOffsetStart,
                int stackOffsetEnd,
                String method,
                String evidence
        ) {
            this.value = value;
            this.address = address;
            this.functionName = functionName;
            this.byteCount = byteCount;
            this.stackOffsetStart = stackOffsetStart;
            this.stackOffsetEnd = stackOffsetEnd;
            this.method = method;
            this.evidence = evidence;
        }
    }

    private static class StackWrite {
        final int offset;
        final byte[] bytes;

        StackWrite(int offset, byte[] bytes) {
            this.offset = offset;
            this.bytes = bytes;
        }
    }

    public static List<StackString> scanFunction(Function func, Listing listing) {
        List<StackString> results = new ArrayList<>();
        if (func == null || listing == null || func.getBody().isEmpty()) return results;

        InstructionIterator instructions = listing.getInstructions(func.getBody(), true);
        StringBuilder current = new StringBuilder();
        String startAddress = null;
        int startOffset = 0;
        int expectedOffset = 0;

        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            StackWrite write = findImmediateStackWrite(instruction);

            if (write == null || !isPrintable(write.bytes)
                    || write.bytes.length > MAX_STRING_BYTES) {
                flush(results, current, startAddress, func, startOffset, expectedOffset);
                startAddress = null;
                continue;
            }

            boolean startsNewRun = current.length() == 0
                    || write.offset != expectedOffset
                    || current.length() + write.bytes.length > MAX_STRING_BYTES;

            if (startsNewRun && current.length() > 0) {
                flush(results, current, startAddress, func, startOffset, expectedOffset);
                startAddress = null;
            }

            if (current.length() == 0) {
                startAddress = instruction.getAddress().toString();
                startOffset = write.offset;
            }

            appendBytes(current, write.bytes);
            expectedOffset = write.offset + write.bytes.length;
        }

        flush(results, current, startAddress, func, startOffset, expectedOffset);
        return results;
    }

    private static StackWrite findImmediateStackWrite(Instruction instruction) {
        if (instruction == null) return null;
        String mnemonic = instruction.getMnemonicString().toUpperCase();
        if (!mnemonic.startsWith("MOV") && !mnemonic.startsWith("STR")) return null;

        System.out.println("[STACK-DEBUG] " + instruction.getAddress() + " " + instruction);
        for (Reference reference : instruction.getReferencesFrom()) {
            System.out.println("[STACK-DEBUG] REF class=" + reference.getClass().getName()
                    + " stack=" + reference.isStackReference()
                    + " type=" + reference.getReferenceType()
                    + " operand=" + reference.getOperandIndex()
                    + " value=" + reference);
        }
        PcodeOp[] debugPcode = instruction.getPcode();
        if (debugPcode != null) {
            for (PcodeOp operation : debugPcode) {
                System.out.println("[STACK-DEBUG] PCODE " + operation);
            }
        }

        List<StackReference> stackWrites = new ArrayList<>();
        for (Reference reference : instruction.getReferencesFrom()) {
            if (!(reference instanceof StackReference)
                    || !reference.getReferenceType().isWrite()) {
                continue;
            }

            int operandIndex = reference.getOperandIndex();
            if (operandIndex < 0 || operandIndex >= instruction.getNumOperands()) continue;
            if (!ghidra.program.model.lang.OperandType.doesWrite(
                    instruction.getOperandType(operandIndex))) {
                continue;
            }
            stackWrites.add((StackReference) reference);
        }
        if (stackWrites.size() != 1) return null;

        PcodeOp[] pcode = instruction.getPcode();
        if (pcode == null || pcode.length == 0) return null;

        StackWrite candidate = null;
        for (PcodeOp operation : pcode) {
            if (operation == null || operation.getOpcode() != PcodeOp.STORE
                    || operation.getNumInputs() < 3) {
                continue;
            }

            Varnode storedValue = operation.getInput(2);
            if (storedValue == null || !storedValue.isConstant()) continue;

            int size = storedValue.getSize();
            if (size < 1 || size > MAX_STORE_BYTES) continue;

            byte[] bytes = constantBytes(
                    storedValue.getOffset(),
                    size,
                    instruction.getProgram().getLanguage().isBigEndian()
            );
            if (!isPrintable(bytes)) continue;

            if (candidate != null) return null;
            candidate = new StackWrite(stackWrites.get(0).getStackOffset(), bytes);
        }
        return candidate;
    }

    private static byte[] constantBytes(long value, int size, boolean bigEndian) {
        byte[] bytes = new byte[size];
        for (int index = 0; index < size; index++) {
            int shiftIndex = bigEndian ? size - 1 - index : index;
            bytes[index] = (byte) ((value >>> (shiftIndex * 8)) & 0xff);
        }
        return bytes;
    }

    private static boolean isPrintable(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return false;
        for (byte value : bytes) {
            int unsigned = value & 0xff;
            if (unsigned < 0x20 || unsigned > 0x7e) return false;
        }
        return true;
    }

    private static void appendBytes(StringBuilder builder, byte[] bytes) {
        for (byte value : bytes) builder.append((char) (value & 0xff));
    }

    private static void flush(
            List<StackString> results,
            StringBuilder current,
            String startAddress,
            Function function,
            int startOffset,
            int endOffset
    ) {
        if (current.length() >= MIN_STRING_BYTES && startAddress != null) {
            int byteCount = current.length();
            String method = "contiguous_stack_immediate_stores";
            String evidence = byteCount + " printable ASCII bytes from consecutive "
                    + "constant stack writes at offsets [" + startOffset + ", " + endOffset + ")";
            results.add(new StackString(
                    current.toString(),
                    startAddress,
                    function.getName(),
                    byteCount,
                    startOffset,
                    endOffset,
                    method,
                    evidence
            ));
        }
        current.setLength(0);
    }
}
