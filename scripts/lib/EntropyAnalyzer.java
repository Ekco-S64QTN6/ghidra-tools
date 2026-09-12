package lib;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Calculates byte-level Shannon entropy (0.00 - 8.00) over memory blocks
 * and detects known packer signatures and high-entropy packed sections.
 */
public class EntropyAnalyzer {

    public static final double HIGH_ENTROPY_THRESHOLD = 7.2;

    /**
     * Calculates Shannon entropy (H = -sum(p * log2(p))) for a Ghidra MemoryBlock.
     * Returns a value between 0.0 (uniform bytes) and 8.0 (maximum theoretical randomness).
     */
    public static double calculateBlockEntropy(MemoryBlock block) {
        if (block == null || !block.isInitialized() || block.getSize() == 0) {
            return 0.0;
        }

        long[] counts = new long[256];
        byte[] buf = new byte[16384];
        long remaining = block.getSize();
        Address addr = block.getStart();
        long totalRead = 0;

        while (remaining > 0) {
            int toRead = (int) Math.min(remaining, (long) buf.length);
            try {
                int read = block.getBytes(addr, buf, 0, toRead);
                if (read <= 0) break;
                for (int i = 0; i < read; i++) {
                    counts[buf[i] & 0xFF]++;
                }
                totalRead += read;
                addr = addr.add(read);
                remaining -= read;
            } catch (Exception e) {
                break;
            }
        }

        if (totalRead == 0) return 0.0;

        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (counts[i] > 0) {
                double p = (double) counts[i] / totalRead;
                entropy -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return entropy;
    }

    /**
     * Checks if an entropy value exceeds the suspicious packed/encrypted threshold.
     */
    public static boolean isHighEntropy(double entropy) {
        return entropy > HIGH_ENTROPY_THRESHOLD;
    }

    /**
     * Returns human-readable status string for an entropy level.
     */
    public static String getEntropyStatus(double entropy, boolean isHigh) {
        if (isHigh || isHighEntropy(entropy)) return "PACKED/CRYPT";
        if (entropy > 6.0) return "MODERATE";
        return "NORMAL";
    }

    /**
     * Detects known packer names based on section / block naming conventions.
     */
    public static String detectPacker(String blockName) {
        if (blockName == null) return "";
        String lower = blockName.toLowerCase();
        if (lower.contains("upx0") || lower.contains("upx1") || lower.contains("upx2")) {
            return "UPX Packer";
        } else if (lower.contains("aspack")) {
            return "ASPack Packer";
        } else if (lower.contains("themida") || lower.contains(".themida")) {
            return "Themida / WinLicense";
        } else if (lower.contains(".mpress") || lower.contains("mpress")) {
            return "MPRESS Packer";
        } else if (lower.contains(".petite") || lower.contains("petite")) {
            return "PEtite Packer";
        }
        return "";
    }
}
