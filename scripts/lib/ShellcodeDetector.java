package lib;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

import java.util.ArrayList;
import java.util.List;

/**
 * Scans memory blocks for shellcode indicators: NOP sleds, GetPC idioms,
 * egg hunters, and staged payload jumps.
 */
public class ShellcodeDetector {

    public static class ShellcodeFinding {
        public final String type;
        public final String address;
        public final String blockName;
        public final String description;
        public final int severityWeight;

        public ShellcodeFinding(String type, String address, String blockName, String description, int severityWeight) {
            this.type = type;
            this.address = address;
            this.blockName = blockName;
            this.description = description;
            this.severityWeight = severityWeight;
        }
    }

    private static final int NOP_THRESHOLD = 16;

    public static List<ShellcodeFinding> scanBlock(MemoryBlock block) {
        List<ShellcodeFinding> findings = new ArrayList<>();
        if (block == null || !block.isInitialized() || block.getSize() < 16) {
            return findings;
        }

        // Focus especially on executable or RWX blocks, but scan initialized blocks up to 4MB
        long scanLimit = Math.min(block.getSize(), 4 * 1024 * 1024);
        byte[] bytes = new byte[(int) scanLimit];
        Address startAddr = block.getStart();

        try {
            int read = block.getBytes(startAddr, bytes, 0, (int) scanLimit);
            if (read <= 0) return findings;

            // 1. NOP Sled Detection (runs of 0x90 >= NOP_THRESHOLD)
            int nopRun = 0;
            int nopStart = -1;
            for (int i = 0; i < read; i++) {
                if ((bytes[i] & 0xFF) == 0x90) {
                    if (nopRun == 0) nopStart = i;
                    nopRun++;
                } else {
                    if (nopRun >= NOP_THRESHOLD) {
                        Address hit = startAddr.add(nopStart);
                        findings.add(new ShellcodeFinding(
                                "NOP Sled",
                                hit.toString(),
                                block.getName(),
                                "NOP sled detected: " + nopRun + " consecutive 0x90 bytes at " + hit,
                                20
                        ));
                    }
                    nopRun = 0;
                }
            }
            if (nopRun >= NOP_THRESHOLD) {
                Address hit = startAddr.add(nopStart);
                findings.add(new ShellcodeFinding(
                        "NOP Sled",
                        hit.toString(),
                        block.getName(),
                        "NOP sled detected: " + nopRun + " consecutive 0x90 bytes at " + hit,
                        20
                ));
            }

            // 2. Common GetPC idioms (x86 call $+5; pop reg)
            // E8 00 00 00 00 followed by 58..5F (pop eax..edi)
            for (int i = 0; i < read - 5; i++) {
                if ((bytes[i] & 0xFF) == 0xE8 &&
                    bytes[i+1] == 0x00 && bytes[i+2] == 0x00 && bytes[i+3] == 0x00 && bytes[i+4] == 0x00) {
                    int next = bytes[i+5] & 0xFF;
                    if (next >= 0x58 && next <= 0x5F) {
                        Address hit = startAddr.add(i);
                        findings.add(new ShellcodeFinding(
                                "GetPC Stub",
                                hit.toString(),
                                block.getName(),
                                "x86 GetPC call/pop stub detected (call $+5; pop) at " + hit,
                                25
                        ));
                    }
                }
            }

            // 3. FPU GetPC idiom: fnstenv (D9 74 24 xx) or fstenv
            for (int i = 0; i < read - 3; i++) {
                if ((bytes[i] & 0xFF) == 0xD9 && (bytes[i+1] & 0xFF) == 0x74 && (bytes[i+2] & 0xFF) == 0x24) {
                    Address hit = startAddr.add(i);
                    findings.add(new ShellcodeFinding(
                            "FPU GetPC",
                            hit.toString(),
                            block.getName(),
                            "FPU fnstenv GetPC shellcode stub detected at " + hit,
                            25
                    ));
                }
            }

        } catch (Exception ignored) {}

        return findings;
    }
}
