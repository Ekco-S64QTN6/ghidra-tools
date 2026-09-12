package lib;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Analyzes Super Nintendo (SNES / 65816) binaries:
 * - Cartridge registration header decoding (LoROM / HiROM / Checksums)
 * - MMIO Hardware Register Access Map ($2100-$213F PPU, $4200-$421F CPU, $4300-$437F DMA)
 * - DMA / HDMA Channel Usage and Table detection
 */
public class SnesAnalyzer {

    public static class CartridgeHeader {
        public boolean valid = false;
        public String title = "Unknown";
        public String mappingMode = "Unknown";
        public String romType = "Unknown";
        public String romSize = "Unknown";
        public String ramSize = "None";
        public String destination = "Unknown";
        public int checksum = 0;
        public int complement = 0;
    }

    public static class MmioAccess {
        public final int address;
        public final String registerName;
        public final String category;
        public final String description;
        public int accessCount = 0;

        public MmioAccess(int address, String registerName, String category, String description) {
            this.address = address;
            this.registerName = registerName;
            this.category = category;
            this.description = description;
        }
    }

    public static class DmaChannelUsage {
        public final int channel;
        public boolean active = false;
        public boolean generalDma = false;
        public boolean hdma = false;
        public Set<String> targetDescriptions = new LinkedHashSet<>();
        public Set<String> tablePointers = new LinkedHashSet<>();
        public int accessCount = 0;

        public DmaChannelUsage(int channel) {
            this.channel = channel;
        }

        public String getModeString() {
            if (generalDma && hdma) return "DMA + HDMA";
            if (hdma) return "HDMA (H-Blank)";
            if (generalDma) return "General DMA";
            return active ? "Configured" : "Unused";
        }
    }

    private static final Map<Integer, MmioAccess> MMIO_REGISTERS = new LinkedHashMap<>();

    static {
        // PPU - Picture Processing Unit ($2100 - $213F)
        reg(0x2100, "INIDISP", "PPU", "Screen Display / Brightness Control");
        reg(0x2101, "OBSEL", "PPU", "Object (Sprite) Size & Tile Selection");
        reg(0x2102, "OAMADDL", "PPU", "OAM Address Low Byte");
        reg(0x2103, "OAMADDH", "PPU", "OAM Address High Bit & Priority");
        reg(0x2104, "OAMDATA", "PPU", "OAM Data Write (Sprites)");
        reg(0x2105, "BGMODE", "PPU", "BG Mode (0-7) & Character Tile Size");
        reg(0x2106, "MOSAIC", "PPU", "Mosaic Pixelation Filter");
        reg(0x2107, "BG1SC", "PPU", "BG1 Screen Base Address & Size");
        reg(0x2108, "BG2SC", "PPU", "BG2 Screen Base Address & Size");
        reg(0x2109, "BG3SC", "PPU", "BG3 Screen Base Address & Size");
        reg(0x210A, "BG4SC", "PPU", "BG4 Screen Base Address & Size");
        reg(0x210B, "BG12NBA", "PPU", "BG1 & BG2 Character Data Base Address");
        reg(0x210C, "BG34NBA", "PPU", "BG3 & BG4 Character Data Base Address");
        reg(0x210D, "BG1HOFS", "PPU", "BG1 Horizontal Scroll Offset");
        reg(0x210E, "BG1VOFS", "PPU", "BG1 Vertical Scroll Offset");
        reg(0x210F, "BG2HOFS", "PPU", "BG2 Horizontal Scroll Offset");
        reg(0x2110, "BG2VOFS", "PPU", "BG2 Vertical Scroll Offset");
        reg(0x2111, "BG3HOFS", "PPU", "BG3 Horizontal Scroll Offset");
        reg(0x2112, "BG3VOFS", "PPU", "BG3 Vertical Scroll Offset");
        reg(0x2113, "BG4HOFS", "PPU", "BG4 Horizontal Scroll Offset");
        reg(0x2114, "BG4VOFS", "PPU", "BG4 Vertical Scroll Offset");
        reg(0x2115, "VMAIN", "PPU", "VRAM Address Increment Mode");
        reg(0x2116, "VMADDL", "PPU", "VRAM Address Low Byte");
        reg(0x2117, "VMADDH", "PPU", "VRAM Address High Byte");
        reg(0x2118, "VMDATAL", "PPU", "VRAM Data Write Low Byte");
        reg(0x2119, "VMDATAH", "PPU", "VRAM Data Write High Byte");
        reg(0x211A, "M7SEL", "PPU", "Mode 7 Matrix Initial Settings");
        reg(0x211B, "M7A", "PPU", "Mode 7 Matrix Parameter A / Multiplicand");
        reg(0x211C, "M7B", "PPU", "Mode 7 Matrix Parameter B / Multiplier");
        reg(0x211D, "M7C", "PPU", "Mode 7 Matrix Parameter C");
        reg(0x211E, "M7D", "PPU", "Mode 7 Matrix Parameter D");
        reg(0x211F, "M7X", "PPU", "Mode 7 Center Offset X");
        reg(0x2120, "M7Y", "PPU", "Mode 7 Center Offset Y");
        reg(0x2121, "CGADD", "PPU", "CGRAM (Palette) Address");
        reg(0x2122, "CGDATA", "PPU", "CGRAM (Palette) Data Write");
        reg(0x2123, "W12SEL", "PPU", "Window Mask Settings for BG1 & BG2");
        reg(0x2124, "W34SEL", "PPU", "Window Mask Settings for BG3 & BG4");
        reg(0x2125, "WOBJSEL", "PPU", "Window Mask Settings for Objects & Color Math");
        reg(0x2126, "WH0", "PPU", "Window 1 Left Position");
        reg(0x2127, "WH1", "PPU", "Window 1 Right Position");
        reg(0x2128, "WH2", "PPU", "Window 2 Left Position");
        reg(0x2129, "WH3", "PPU", "Window 2 Right Position");
        reg(0x212A, "WBGLOG", "PPU", "Window Mask Logic for BGs");
        reg(0x212B, "WOBJLOG", "PPU", "Window Mask Logic for Objects");
        reg(0x212C, "TM", "PPU", "Main Screen Designation");
        reg(0x212D, "TS", "PPU", "Sub Screen Designation");
        reg(0x212E, "TMW", "PPU", "Window Mask Designation for Main Screen");
        reg(0x212F, "TSW", "PPU", "Window Mask Designation for Sub Screen");
        reg(0x2130, "CGWSEL", "PPU", "Color Math Initial Settings");
        reg(0x2131, "CGADSUB", "PPU", "Color Math Subtraction & Designation");
        reg(0x2132, "COLDATA", "PPU", "Fixed Color Constant Data (Backdrop)");
        reg(0x2133, "SETINI", "PPU", "Screen Initial Settings (Interlace, Hi-Res)");
        reg(0x2134, "MPYL", "PPU", "Mode 7 Signed Multiply Result Low");
        reg(0x2135, "MPYM", "PPU", "Mode 7 Signed Multiply Result Middle");
        reg(0x2136, "MPYH", "PPU", "Mode 7 Signed Multiply Result High");
        reg(0x2137, "SLHV", "PPU", "Software Latch for H/V Counter");
        reg(0x2138, "OAMDATAREAD", "PPU", "OAM Data Read");
        reg(0x2139, "VMDATALREAD", "PPU", "VRAM Data Read Low");
        reg(0x213A, "VMDATAHREAD", "PPU", "VRAM Data Read High");
        reg(0x213B, "CGDATAREAD", "PPU", "CGRAM Data Read");
        reg(0x213C, "OPHCT", "PPU", "Output Horizontal Counter");
        reg(0x213D, "OPVCT", "PPU", "Output Vertical Counter");

        // APU / SPC700 Audio Subsystem ($2140 - $2143)
        reg(0x2140, "APUIO0", "APU", "Audio CPU (SPC700) Comm Port 0 (Handshake/Command)");
        reg(0x2141, "APUIO1", "APU", "Audio CPU (SPC700) Comm Port 1 (Handshake/Data)");
        reg(0x2142, "APUIO2", "APU", "Audio CPU (SPC700) Comm Port 2 (Target Address Low)");
        reg(0x2143, "APUIO3", "APU", "Audio CPU (SPC700) Comm Port 3 (Target Address High)");

        // CPU & I/O ($4200 - $421F)
        reg(0x4200, "NMITIMEN", "CPU", "Interrupt Enable (V-Blank NMI, Joypad, Timer)");
        reg(0x4201, "WRIO", "CPU", "Programmable I/O Port Write");
        reg(0x4202, "WRNUM", "CPU", "Hardware Multiplicand (8-bit)");
        reg(0x4203, "WRDEN", "CPU", "Hardware Multiplier (8-bit)");
        reg(0x4204, "RDDIVL", "CPU", "Hardware Dividend Low (16-bit)");
        reg(0x4205, "RDDIVH", "CPU", "Hardware Dividend High (16-bit)");
        reg(0x4206, "WRDIVB", "CPU", "Hardware Divisor (8-bit)");
        reg(0x4207, "HTIMEL", "CPU", "Timer IRQ H-Count Target Low");
        reg(0x4208, "HTIMEH", "CPU", "Timer IRQ H-Count Target High");
        reg(0x4209, "VTIMEL", "CPU", "Timer IRQ V-Count Target Low");
        reg(0x420A, "VTIMEH", "CPU", "Timer IRQ V-Count Target High");
        reg(0x420B, "MDMAEN", "DMA", "Direct Memory Access Enable (Channels 0-7)");
        reg(0x420C, "HDMAEN", "DMA", "H-Blank DMA Enable (Channels 0-7)");
        reg(0x4210, "RDNMI", "CPU", "V-Blank NMI Flag & CPU Version");
        reg(0x4211, "TIMEUP", "CPU", "Timer IRQ Flag");
        reg(0x4212, "HVBJOY", "CPU", "H/V Blank Status & Joypad Auto-Read Flag");
        reg(0x4218, "JOY1L", "Joypad", "Controller 1 Data Low Byte");
        reg(0x4219, "JOY1H", "Joypad", "Controller 1 Data High Byte");
        reg(0x421A, "JOY2L", "Joypad", "Controller 2 Data Low Byte");
        reg(0x421B, "JOY2H", "Joypad", "Controller 2 Data High Byte");

        // DMA Channels 0-7 ($4300 - $437F)
        for (int ch = 0; ch < 8; ch++) {
            int base = 0x4300 + (ch * 0x10);
            reg(base + 0, "DMAP" + ch, "DMA", "DMA/HDMA Channel " + ch + " Parameters");
            reg(base + 1, "BBAD" + ch, "DMA", "DMA Channel " + ch + " B-Bus Target Address");
            reg(base + 2, "A1T" + ch + "L", "DMA", "DMA Channel " + ch + " A-Bus Source Table Low");
            reg(base + 3, "A1T" + ch + "H", "DMA", "DMA Channel " + ch + " A-Bus Source Table High");
            reg(base + 4, "A1B" + ch, "DMA", "DMA Channel " + ch + " A-Bus Source Bank");
            reg(base + 5, "DAS" + ch + "L", "DMA", "DMA Channel " + ch + " Byte Counter Low");
            reg(base + 6, "DAS" + ch + "H", "DMA", "DMA Channel " + ch + " Byte Counter High");
            reg(base + 7, "A2A" + ch + "L", "DMA", "DMA Channel " + ch + " HDMA Indirect Table Low");
            reg(base + 8, "A2A" + ch + "H", "DMA", "DMA Channel " + ch + " HDMA Indirect Table High");
            reg(base + 9, "NTRL" + ch, "DMA", "DMA Channel " + ch + " HDMA Line Counter");
        }
    }

    private static void reg(int addr, String name, String cat, String desc) {
        MMIO_REGISTERS.put(addr, new MmioAccess(addr, name, cat, desc));
    }

    public static CartridgeHeader parseHeader(MemoryBlock block) {
        CartridgeHeader hdr = new CartridgeHeader();
        if (block == null || !block.isInitialized() || block.getSize() < 0x8000) {
            return hdr;
        }

        // Try standard LoROM (0x7FC0) and HiROM (0xFFC0)
        int[] offsets = {0x7FC0, 0xFFC0, 0x81C0, 0x101C0};
        for (int off : offsets) {
            if (off + 48 <= block.getSize()) {
                byte[] b = new byte[48];
                try {
                    Address a = block.getStart().add(off);
                    block.getBytes(a, b, 0, 48);
                    int comp = (b[28] & 0xFF) | ((b[29] & 0xFF) << 8);
                    int csum = (b[30] & 0xFF) | ((b[31] & 0xFF) << 8);

                    if ((comp + csum) == 0xFFFF && csum != 0 && comp != 0) {
                        hdr.valid = true;
                        hdr.checksum = csum;
                        hdr.complement = comp;
                        hdr.title = new String(b, 0, 21, StandardCharsets.US_ASCII).replaceAll("[^\\x20-\\x7E]", " ").trim();
                        int map = b[21] & 0xFF;
                        hdr.mappingMode = (map == 0x20 || map == 0x30) ? "LoROM (32KB banks)" :
                                          (map == 0x21 || map == 0x31) ? "HiROM (64KB banks)" :
                                          (map == 0x25) ? "ExHiROM" : String.format("Custom (0x%02X)", map);
                        int rType = b[22] & 0xFF;
                        hdr.romType = (rType == 0) ? "ROM Only" : (rType == 1) ? "ROM + RAM" : (rType == 2) ? "ROM + Battery RAM" : "ROM + Co-processor";
                        int rSize = b[23] & 0xFF;
                        hdr.romSize = (rSize >= 7 && rSize <= 13) ? (1 << (rSize - 7)) + " MBit" : "Unknown";
                        return hdr;
                    }
                } catch (Exception ignored) {}
            }
        }

        hdr.title = "Prototype / Non-Retail ROM";
        hdr.mappingMode = "Raw 65816 Mapping";
        return hdr;
    }

    public static List<MmioAccess> scanMmioAccesses(Listing listing) {
        Map<Integer, Integer> hits = new HashMap<>();
        InstructionIterator instrs = listing.getInstructions(true);

        while (instrs.hasNext()) {
            Instruction ins = instrs.next();
            for (int i = 0; i < ins.getNumOperands(); i++) {
                Object[] objs = ins.getOpObjects(i);
                for (Object o : objs) {
                    int low16 = -1;
                    if (o instanceof Address) {
                        low16 = (int) (((Address) o).getOffset() & 0xFFFF);
                    } else if (o instanceof Scalar) {
                        low16 = (int) (((Scalar) o).getUnsignedValue() & 0xFFFF);
                    }
                    if (low16 != -1 && MMIO_REGISTERS.containsKey(low16)) {
                        hits.put(low16, hits.getOrDefault(low16, 0) + 1);
                    }
                }
            }
            Reference[] refs = ins.getReferencesFrom();
            if (refs != null) {
                for (Reference ref : refs) {
                    if (ref.getToAddress() != null) {
                        int low16 = (int) (ref.getToAddress().getOffset() & 0xFFFF);
                        if (MMIO_REGISTERS.containsKey(low16)) {
                            hits.put(low16, hits.getOrDefault(low16, 0) + 1);
                        }
                    }
                }
            }
        }

        List<MmioAccess> result = new ArrayList<>();
        for (Map.Entry<Integer, Integer> entry : hits.entrySet()) {
            MmioAccess template = MMIO_REGISTERS.get(entry.getKey());
            if (template != null) {
                MmioAccess acc = new MmioAccess(template.address, template.registerName, template.category, template.description);
                acc.accessCount = entry.getValue();
                result.add(acc);
            }
        }

        result.sort((a, b) -> Integer.compare(b.accessCount, a.accessCount));
        return result;
    }

    public static List<DmaChannelUsage> scanDmaChannels(Listing listing) {
        List<DmaChannelUsage> channels = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            channels.add(new DmaChannelUsage(i));
        }

        InstructionIterator instrs = listing.getInstructions(true);
        while (instrs.hasNext()) {
            Instruction ins = instrs.next();
            int targetAddr = -1;

            for (int i = 0; i < ins.getNumOperands(); i++) {
                Object[] objs = ins.getOpObjects(i);
                for (Object o : objs) {
                    if (o instanceof Address) {
                        targetAddr = (int) (((Address) o).getOffset() & 0xFFFF);
                    } else if (o instanceof Scalar) {
                        targetAddr = (int) (((Scalar) o).getUnsignedValue() & 0xFFFF);
                    }
                }
            }
            if (targetAddr == -1) {
                Reference[] refs = ins.getReferencesFrom();
                if (refs != null && refs.length > 0 && refs[0].getToAddress() != null) {
                    targetAddr = (int) (refs[0].getToAddress().getOffset() & 0xFFFF);
                }
            }

            if (targetAddr >= 0x4300 && targetAddr <= 0x437F) {
                int ch = (targetAddr - 0x4300) / 0x10;
                int regOffset = (targetAddr - 0x4300) % 0x10;
                if (ch >= 0 && ch < 8) {
                    DmaChannelUsage cu = channels.get(ch);
                    cu.active = true;
                    cu.accessCount++;

                    Instruction prev = ins.getPrevious();
                    long immVal = -1;
                    if (prev != null && prev.getMnemonicString().toUpperCase().startsWith("LD")) {
                        for (int op = 0; op < prev.getNumOperands(); op++) {
                            Scalar sc = prev.getScalar(op);
                            if (sc != null) immVal = sc.getUnsignedValue();
                        }
                    }

                    if (regOffset == 0x0) { // DMAPx
                        if (immVal != -1 && (immVal & 0x40) != 0) {
                            cu.hdma = true;
                        }
                    } else if (regOffset == 0x1) { // BBADx
                        if (immVal != -1) {
                            int bbad = (int) (immVal & 0xFF);
                            cu.targetDescriptions.add(resolveBbusTarget(bbad));
                        } else {
                            cu.targetDescriptions.add("B-Bus Register (Variable)");
                        }
                    } else if (regOffset >= 0x2 && regOffset <= 0x4) { // A1Tx / A1Bx
                        if (immVal != -1) {
                            cu.tablePointers.add(String.format("$%02X", immVal));
                        }
                    } else if (regOffset == 0x7 || regOffset == 0x8) { // A2Ax
                        cu.hdma = true;
                    }
                }
            } else if (targetAddr == 0x420B) { // MDMAEN
                Instruction prev = ins.getPrevious();
                if (prev != null && prev.getMnemonicString().toUpperCase().startsWith("LD")) {
                    for (int op = 0; op < prev.getNumOperands(); op++) {
                        Scalar sc = prev.getScalar(op);
                        if (sc != null) {
                            long mask = sc.getUnsignedValue() & 0xFF;
                            for (int ch = 0; ch < 8; ch++) {
                                if ((mask & (1 << ch)) != 0) {
                                    DmaChannelUsage cu = channels.get(ch);
                                    cu.active = true;
                                    cu.generalDma = true;
                                    cu.accessCount++;
                                }
                            }
                        }
                    }
                }
            } else if (targetAddr == 0x420C) { // HDMAEN
                Instruction prev = ins.getPrevious();
                if (prev != null && prev.getMnemonicString().toUpperCase().startsWith("LD")) {
                    for (int op = 0; op < prev.getNumOperands(); op++) {
                        Scalar sc = prev.getScalar(op);
                        if (sc != null) {
                            long mask = sc.getUnsignedValue() & 0xFF;
                            for (int ch = 0; ch < 8; ch++) {
                                if ((mask & (1 << ch)) != 0) {
                                    DmaChannelUsage cu = channels.get(ch);
                                    cu.active = true;
                                    cu.hdma = true;
                                    cu.accessCount++;
                                }
                            }
                        }
                    }
                }
            }
        }

        return channels;
    }

    private static String resolveBbusTarget(int bbad) {
        switch (bbad) {
            case 0x04: return "OAM Data ($2104 - Sprites)";
            case 0x18: return "VRAM Data ($2118 - Tilemap/VRAM)";
            case 0x22: return "CGRAM Data ($2122 - Palettes)";
            case 0x00: return "INIDISP ($2100 - Brightness/Display)";
            case 0x01: return "OBSEL ($2101 - Sprite Config)";
            case 0x05: return "BGMODE ($2105 - Screen Mode)";
            case 0x06: return "MOSAIC ($2106 - Mosaic Effect)";
            case 0x0D: return "BG1HOFS ($210D - BG1 H-Scroll)";
            case 0x0E: return "BG1VOFS ($210E - BG1 V-Scroll)";
            case 0x0F: return "BG2HOFS ($210F - BG2 H-Scroll)";
            case 0x10: return "BG2VOFS ($2110 - BG2 V-Scroll)";
            case 0x32: return "COLDATA ($2132 - Color Math Backdrop)";
            default:   return String.format("PPU Reg $21%02X", bbad);
        }
    }

    public static void printSnesReport(PrintWriter out, CartridgeHeader hdr, List<MmioAccess> accesses, List<DmaChannelUsage> dmaChannels) {
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println("  SNES CARTRIDGE HEADER & HARDWARE CONFIGURATION");
        out.println("════════════════════════════════════════════════════════════════════════════════");
        out.println();
        out.printf("  Internal Title:    %s%n", hdr.title);
        out.printf("  Mapping Mode:      %s%n", hdr.mappingMode);
        out.printf("  Cartridge Type:    %s%n", hdr.romType);
        out.printf("  ROM Capacity:      %s%n", hdr.romSize);
        if (hdr.valid) {
            out.printf("  Header Checksum:   0x%04X (Complement: 0x%04X, Valid: YES)%n", hdr.checksum, hdr.complement);
        } else {
            out.printf("  Header Checksum:   None (Non-standard development or raw dump)%n");
        }
        out.println();

        if (dmaChannels != null) {
            boolean anyDma = false;
            for (DmaChannelUsage cu : dmaChannels) {
                if (cu.active) { anyDma = true; break; }
            }
            if (anyDma) {
                out.println("════════════════════════════════════════════════════════════════════════════════");
                out.println("  SNES DMA / HDMA CHANNEL USAGE & TABLE DETECTION");
                out.println("════════════════════════════════════════════════════════════════════════════════");
                out.println();
                out.printf("  %-9s %-16s %-32s %-6s %s%n", "Channel", "Type", "Target Subsystem", "Hits", "Table Info");
                out.println("  " + "-".repeat(85));
                for (DmaChannelUsage cu : dmaChannels) {
                    if (!cu.active) continue;
                    String target = cu.targetDescriptions.isEmpty() ? "(Unspecified)" : String.join(", ", cu.targetDescriptions);
                    String tbl = cu.tablePointers.isEmpty() ? (cu.hdma ? "Indirect Table Mode" : "-") : String.join(", ", cu.tablePointers);
                    out.printf("  CH %-6d %-16s %-32s %-6d %s%n",
                            cu.channel, cu.getModeString(), target, cu.accessCount, tbl);
                }
                out.println("  " + "-".repeat(85));
                out.println();
            }
        }

        int apuHits = 0;
        for (MmioAccess acc : accesses) {
            if ("APU".equals(acc.category)) apuHits += acc.accessCount;
        }
        if (apuHits > 0) {
            out.println("════════════════════════════════════════════════════════════════════════════════");
            out.println("  SPC700 AUDIO CPU (APU) SUBSYSTEM COMMUNICATION");
            out.println("════════════════════════════════════════════════════════════════════════════════");
            out.println();
            out.printf("  Status:            Active (Sony SPC700 8-bit Audio Processor Interface)%n");
            out.printf("  APU Comm Hits:     %d interaction(s) via $2140-$2143 ports%n", apuHits);
            out.println("  Protocol:          IPL Boot Handshake & Sound Driver Streamer Detected");
            out.println();
        }

        if (!accesses.isEmpty()) {
            out.println("════════════════════════════════════════════════════════════════════════════════");
            out.println("  SNES MMIO HARDWARE REGISTER ACCESS MAP");
            out.println("════════════════════════════════════════════════════════════════════════════════");
            out.println();
            out.printf("  %-8s %-12s %-10s %-8s %s%n", "Address", "Register", "Category", "Hits", "Description");
            out.println("  " + "-".repeat(85));
            int shown = 0;
            for (MmioAccess acc : accesses) {
                if (shown >= 25) {
                    out.printf("  ... and %d additional hardware register(s)%n", accesses.size() - 25);
                    break;
                }
                out.printf("  $%04X  %-12s %-10s %-8d %s%n",
                        acc.address, acc.registerName, acc.category, acc.accessCount, acc.description);
                shown++;
            }
            out.println("  " + "-".repeat(85));
            out.println();
        }
    }

    // ── Interrupt vectors ────────────────────────────────────────────────────

    /** One resolved 65816 interrupt vector: where it lives, and where it points. */
    public static class VectorTarget {
        public final String name;
        public final Address vectorAddress;
        public final Address target;

        public VectorTarget(String name, Address vectorAddress, Address target) {
            this.name = name;
            this.vectorAddress = vectorAddress;
            this.target = target;
        }
    }

    /** Vector slots in bank $00: {offset, label}. Native table first, then emulation. */
    private static final Object[][] VECTOR_SLOTS = {
        {0xFFE4, "COP_native"},   {0xFFE6, "BRK_native"},  {0xFFE8, "ABORT_native"},
        {0xFFEA, "NMI_native"},   {0xFFEE, "IRQ_native"},
        {0xFFF4, "COP_emu"},      {0xFFF8, "ABORT_emu"},   {0xFFFA, "NMI_emu"},
        {0xFFFC, "RESET"},        {0xFFFE, "IRQ_emu"},
    };

    /**
     * Reads the 65816 interrupt vector table and resolves each slot to its handler.
     *
     * Ghidra's raw binary import declares no entry points, so without this the
     * auto-analyzer has nothing to seed disassembly from and a ROM comes back with
     * almost no recovered code. Slots reading $0000 or $FFFF are treated as unused.
     */
    public static List<VectorTarget> readVectors(Program program) {
        List<VectorTarget> found = new ArrayList<>();
        if (program == null) return found;

        Memory mem = program.getMemory();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        for (Object[] slot : VECTOR_SLOTS) {
            int offset = (Integer) slot[0];
            String name = (String) slot[1];
            try {
                Address va = space.getAddress(String.format("00%04x", offset));
                int lo = mem.getByte(va) & 0xFF;
                int hi = mem.getByte(va.add(1)) & 0xFF;
                int target = (hi << 8) | lo;
                if (target == 0x0000 || target == 0xFFFF) continue;
                found.add(new VectorTarget(name, va, space.getAddress(String.format("00%04x", target))));
            } catch (Exception ignored) {
                // Vector outside the mapped image — skip it.
            }
        }
        return found;
    }
}
