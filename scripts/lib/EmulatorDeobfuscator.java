package lib;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * P-Code Emulation & XOR Loop Deobfuscator.
 * Analyzes candidate routines with loop density and bitwise/XOR logic
 * to reconstruct runtime-decrypted strings and payload markers.
 */
public class EmulatorDeobfuscator {

    public static class DeobfuscatedString {
        public final String value;
        public final String functionName;
        public final String address;
        public final String method;

        public DeobfuscatedString(String value, String functionName, String address, String method) {
            this.value = value;
            this.functionName = functionName;
            this.address = address;
            this.method = method;
        }
    }

    public static List<DeobfuscatedString> deobfuscateCandidates(Program program, List<Function> candidateFunctions, TaskMonitor monitor) {
        List<DeobfuscatedString> results = new ArrayList<>();
        if (program == null || candidateFunctions == null) return results;

        Set<String> seenValues = new HashSet<>();

        // 1. Static XOR loop pattern scanner across all candidate functions
        for (Function func : candidateFunctions) {
            if (func == null || func.getBody().isEmpty()) continue;
            List<DeobfuscatedString> staticHits = scanStaticXorLoop(program, func);
            for (DeobfuscatedString hit : staticHits) {
                if (seenValues.add(hit.value)) {
                    results.add(hit);
                }
            }
        }

        // 2. Dynamic P-Code Emulation pass on top 3 candidates exhibiting loop/XOR behavior
        String langId = program.getLanguageID().toString().toLowerCase();
        boolean emuSupported = langId.contains("x86") || langId.contains("arm") || langId.contains("mips") || langId.contains("powerpc");
        int emuCount = 0;
        Register spReg = null;
        try {
            spReg = program.getCompilerSpec().getStackPointer();
        } catch (Throwable ignored) {}

        for (Function func : candidateFunctions) {
            if (emuCount >= 3) break;
            if (func == null || func.getBody().isEmpty()) continue;

            boolean hasXor = false;
            InstructionIterator instrs = program.getListing().getInstructions(func.getBody(), true);
            while (instrs.hasNext()) {
                Instruction ins = instrs.next();
                String mnem = ins.getMnemonicString().toUpperCase();
                if (mnem.contains("XOR") || mnem.contains("EOR")) {
                    hasXor = true;
                    break;
                }
            }

            if (!hasXor || !emuSupported) continue;

            EmulatorHelper emu = null;
            try {
                emu = new EmulatorHelper(program);
                Address entry = func.getEntryPoint();
                Register pcReg = emu.getPCRegister();
                if (pcReg != null) {
                    emu.writeRegister(pcReg, entry.getOffset());
                }

                int steps = 0;
                int maxSteps = 250;
                while (steps < maxSteps) {
                    try {
                        if (!emu.step(TaskMonitor.DUMMY)) break;
                    } catch (Throwable t) {
                        break;
                    }
                    steps++;
                }

                // Check emulated stack memory for newly decrypted strings
                if (spReg != null) {
                    try {
                        BigInteger spVal = emu.readRegister(spReg);
                        if (spVal != null) {
                            Address spAddr = entry.getAddressSpace().getAddress(spVal.longValue());
                            byte[] stackBuf = emu.readMemory(spAddr, 64);
                            if (stackBuf != null && stackBuf.length > 0) {
                                List<String> found = extractAsciiStrings(stackBuf, 4);
                                for (String str : found) {
                                    if (seenValues.add(str)) {
                                        results.add(new DeobfuscatedString(str, func.getName(), spAddr.toString(), "P-Code Emulation"));
                                    }
                                }
                            }
                        }
                    } catch (Throwable ignored) {}
                }
                emuCount++;
            } catch (Throwable ignored) {
            } finally {
                if (emu != null) {
                    try { emu.dispose(); } catch (Throwable ignored) {}
                }
            }
        }

        return results;
    }

    private static List<DeobfuscatedString> scanStaticXorLoop(Program program, Function func) {
        List<DeobfuscatedString> hits = new ArrayList<>();
        InstructionIterator instrs = program.getListing().getInstructions(func.getBody(), true);
        Instruction xorInstr = null;
        int xorKey = -1;
        Address targetBufferAddr = null;

        while (instrs.hasNext()) {
            Instruction ins = instrs.next();
            String mnem = ins.getMnemonicString().toUpperCase();
            if (mnem.startsWith("XOR") || mnem.startsWith("EOR")) {
                for (int i = 0; i < ins.getNumOperands(); i++) {
                    Scalar sc = ins.getScalar(i);
                    if (sc != null) {
                        long val = sc.getUnsignedValue();
                        if (val > 0 && val <= 0xFF) {
                            xorKey = (int) val;
                            xorInstr = ins;
                        }
                    }
                }
            }
            for (int i = 0; i < ins.getNumOperands(); i++) {
                Address ref = ins.getAddress(i);
                if (ref != null && program.getMemory().contains(ref)) {
                    MemoryBlock mb = program.getMemory().getBlock(ref);
                    if (mb != null && mb.isInitialized()) {
                        targetBufferAddr = ref;
                    }
                }
            }
        }

        if (xorKey != -1 && targetBufferAddr != null && xorInstr != null) {
            try {
                Memory mem = program.getMemory();
                byte[] buf = new byte[64];
                int count = mem.getBytes(targetBufferAddr, buf);
                if (count > 4) {
                    byte[] decrypted = new byte[count];
                    for (int i = 0; i < count; i++) {
                        decrypted[i] = (byte) ((buf[i] & 0xFF) ^ xorKey);
                    }
                    List<String> found = extractAsciiStrings(decrypted, 4);
                    for (String s : found) {
                        hits.add(new DeobfuscatedString(s, func.getName(), targetBufferAddr.toString(), String.format("XOR 0x%02X Key Loop", xorKey)));
                    }
                }
            } catch (Throwable ignored) {}
        }

        return hits;
    }

    private static List<String> extractAsciiStrings(byte[] bytes, int minLen) {
        List<String> list = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            int ub = b & 0xFF;
            if (ub >= 0x20 && ub <= 0x7E) {
                sb.append((char) ub);
            } else {
                if (sb.length() >= minLen) {
                    list.add(sb.toString());
                }
                sb.setLength(0);
            }
        }
        if (sb.length() >= minLen) {
            list.add(sb.toString());
        }
        return list;
    }
}
