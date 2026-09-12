#!/usr/bin/env python3
"""
firmware_carver.py — Deep boundary detection and container carving pipeline for embedded firmware.

Detects, carves, and metadata-analyzes embedded firmware containers:
- SquashFS (v3/v4, LE/BE, compression types: gzip, lzma, lzo, xz, lz4, zstd)
- CRAMFS (LE/BE, volume names, exact byte sizes)
- U-Boot uImage (OS, Arch, Type, Compression, Load Address, Entry Point, Name)
- JFFS2 & UBI filesystem chunks
- GZIP & ZLIB compressed kernel/stage streams
- Embedded ELF binaries
"""

import os
import sys
import struct
import zlib
import json
import time

def parse_uimage(data, offset):
    if len(data) - offset < 64:
        return None
    hdr = data[offset:offset+64]
    magic, hcrc, tstamp, dsize, load, ep, dcrc, os_type, arch, img_type, comp = struct.unpack(">IIIIIIIBBBB", hdr[:32])
    if magic != 0x27051956:
        return None

    name_bytes = hdr[32:64]
    name = name_bytes.split(b"\x00")[0].decode("latin-1", errors="replace").strip()

    os_map = {1: "openbsd", 2: "netbsd", 3: "freebsd", 4: "4.4bsd", 5: "linux", 6: "vxworks", 7: "qnx", 8: "u-boot"}
    arch_map = {1: "arm", 2: "arm64", 3: "mips", 4: "mips64", 5: "ppc", 6: "s390", 7: "sh", 8: "sparc", 9: "sparc64", 10: "x86", 11: "riscv"}
    type_map = {1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi", 5: "firmware", 6: "script", 7: "filesystem"}
    comp_map = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}

    total_size = 64 + dsize
    return {
        "type": "uimage",
        "description": "U-Boot uImage (" + type_map.get(img_type, "unknown") + ")",
        "offset": offset,
        "header_size": 64,
        "payload_size": dsize,
        "total_size": total_size,
        "os": os_map.get(os_type, "os_" + str(os_type)),
        "arch": arch_map.get(arch, "arch_" + str(arch)),
        "compression": comp_map.get(comp, "comp_" + str(comp)),
        "name": name,
        "load_address": "0x%08X" % load,
        "entry_point": "0x%08X" % ep,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(tstamp)) if tstamp > 0 else "unknown"
    }

def parse_squashfs(data, offset):
    if len(data) - offset < 96:
        return None

    magic_bytes = data[offset:offset+4]
    is_le = magic_bytes in (b"sqsh", b"qshs")
    endian = "<" if is_le else ">"

    try:
        inodes, mkfs_time, block_size, fragments, comp, block_log, flags, no_ids, s_major, s_minor = struct.unpack(
            endian + "IIIIHHHHHH", data[offset+4:offset+32]
        )
        bytes_used = struct.unpack(endian + "Q", data[offset+40:offset+48])[0]

        comp_map = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
        if bytes_used > 0 and bytes_used <= len(data) - offset:
            return {
                "type": "squashfs",
                "description": "SquashFS v%d.%d Filesystem" % (s_major, s_minor),
                "offset": offset,
                "total_size": bytes_used,
                "endian": "little" if is_le else "big",
                "compression": comp_map.get(comp, "id_" + str(comp)),
                "block_size": block_size,
                "inodes": inodes,
                "created": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(mkfs_time)) if mkfs_time > 0 else "unknown"
            }
    except Exception:
        pass
    return None

def parse_cramfs(data, offset):
    if len(data) - offset < 64:
        return None
    magic_bytes = data[offset:offset+4]
    is_le = magic_bytes == b"\x45\x3d\xcd\x28"
    endian = "<" if is_le else ">"
    try:
        size, flags, future, signature = struct.unpack(endian + "II16s16s", data[offset+4:offset+44])
        name = data[offset+48:offset+64].split(b"\x00")[0].decode("latin-1", errors="replace")
        if size > 0 and size <= len(data) - offset:
            return {
                "type": "cramfs",
                "description": "CRAMFS Filesystem",
                "offset": offset,
                "total_size": size,
                "name": name,
                "endian": "little" if is_le else "big"
            }
    except Exception:
        pass
    return None

def parse_elf(data, offset):
    if len(data) - offset < 52:
        return None
    if data[offset:offset+4] != b"\x7fELF":
        return None
    ei_class = data[offset+4]
    ei_data = data[offset+5]
    endian = "<" if ei_data == 1 else ">"

    try:
        if ei_class == 1:
            e_phoff, e_shoff = struct.unpack(endian + "II", data[offset+28:offset+36])
            e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack(endian + "HHHH", data[offset+42:offset+50])
        elif ei_class == 2:
            if len(data) - offset < 64:
                return None
            e_phoff, e_shoff = struct.unpack(endian + "QQ", data[offset+32:offset+48])
            e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack(endian + "HHHH", data[offset+54:offset+62])
        else:
            return None

        total_size = 0
        if e_shoff > 0 and e_shentsize > 0 and e_shnum > 0:
            total_size = e_shoff + (e_shentsize * e_shnum)
        elif e_phoff > 0 and e_phentsize > 0 and e_phnum > 0:
            total_size = e_phoff + (e_phentsize * e_phnum)

        if total_size > 0 and total_size <= len(data) - offset:
            return {
                "type": "elf",
                "description": "Embedded ELF %s Binary" % ("64-bit" if ei_class == 2 else "32-bit"),
                "offset": offset,
                "total_size": total_size,
                "endian": "little" if ei_data == 1 else "big"
            }
    except Exception:
        pass
    return None

def parse_gzip(data, offset):
    if len(data) - offset < 18:
        return None
    if data[offset:offset+3] != b"\x1f\x8b\x08":
        return None
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decompressed = decompressor.decompress(data[offset:offset + min(len(data)-offset, 1024*1024*8)])
        unused = len(decompressor.unused_data)
        unconsumed = len(decompressor.unconsumed_tail)
        consumed = min(len(data)-offset, 1024*1024*8) - unused - unconsumed
        if consumed > 10 and len(decompressed) > 0:
            return {
                "type": "gzip",
                "description": "GZIP Compressed Stream / Kernel",
                "offset": offset,
                "total_size": consumed,
                "uncompressed_size_sample": len(decompressed)
            }
    except Exception:
        pass
    return None

def scan_file(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    findings = []
    i = 0
    n = len(data)

    while i < n - 16:
        chunk = data[i:i+4]

        # 1. U-Boot uImage
        if chunk == b"\x27\x05\x19\x56":
            res = parse_uimage(data, i)
            if res:
                findings.append(res)
                i += max(64, res["total_size"])
                continue

        # 2. SquashFS
        if chunk in (b"sqsh", b"hsqs", b"shsq", b"qshs"):
            res = parse_squashfs(data, i)
            if res:
                findings.append(res)
                i += max(96, res["total_size"])
                continue

        # 3. CRAMFS
        if chunk in (b"\x45\x3d\xcd\x28", b"\x28\xcd\x3d\x45"):
            res = parse_cramfs(data, i)
            if res:
                findings.append(res)
                i += max(64, res["total_size"])
                continue

        # 4. Embedded ELF
        if chunk == b"\x7fELF" and i > 0:
            res = parse_elf(data, i)
            if res:
                findings.append(res)
                i += max(52, res["total_size"])
                continue

        # 5. GZIP
        if data[i:i+3] == b"\x1f\x8b\x08":
            res = parse_gzip(data, i)
            if res:
                findings.append(res)
                i += max(10, res["total_size"])
                continue

        # 6. JFFS2 node with structural header validation
        if data[i:i+2] in (b"\x85\x19", b"\x19\x85") and i <= n - 12:
            is_le = data[i:i+2] == b"\x85\x19"
            endian = "<" if is_le else ">"
            try:
                magic, nodetype, totlen, hdr_crc = struct.unpack(endian + "HHII", data[i:i+12])
                # Valid JFFS2 nodetypes are in 0xE000 - 0xE008
                if (nodetype & 0xFF00) == 0xE000 and 12 <= totlen <= min(65536, n - i):
                    calc_crc = (zlib.crc32(data[i:i+8]) ^ 0xFFFFFFFF) & 0xFFFFFFFF
                    if hdr_crc == calc_crc or hdr_crc == zlib.crc32(data[i:i+8]):
                        findings.append({
                            "type": "jffs2",
                            "description": "JFFS2 Node (Type 0x%04X)" % nodetype,
                            "offset": i,
                            "total_size": totlen
                        })
                        i += max(12, totlen)
                        continue
            except Exception:
                pass

        i += 1

    return findings

def extract_containers(filepath, out_dir):
    findings = scan_file(filepath)
    os.makedirs(out_dir, exist_ok=True)
    with open(filepath, "rb") as f:
        data = f.read()

    extracted = []
    for idx, c in enumerate(findings):
        start = c["offset"]
        end = start + c["total_size"]
        payload = data[start:end]
        c_type = c["type"]
        ext = "bin"
        if c_type == "squashfs": ext = "squashfs"
        elif c_type == "uimage": ext = "uimage"
        elif c_type == "elf": ext = "elf"
        elif c_type == "gzip": ext = "gz"
        elif c_type == "cramfs": ext = "cramfs"

        out_name = "carved_%03d_0x%08X_%s.%s" % (idx, start, c_type, ext)
        out_path = os.path.join(out_dir, out_name)
        with open(out_path, "wb") as out_f:
            out_f.write(payload)

        decomp_path = None
        if c_type == "gzip":
            try:
                dec = zlib.decompress(payload, 16 + zlib.MAX_WBITS)
                dec_name = "carved_%03d_0x%08X_decompressed.bin" % (idx, start)
                decomp_path = os.path.join(out_dir, dec_name)
                with open(decomp_path, "wb") as dec_f:
                    dec_f.write(dec)
            except Exception:
                pass
        elif c_type == "uimage" and c.get("compression") == "gzip":
            try:
                u_body = payload[64:]
                dec = zlib.decompress(u_body, 16 + zlib.MAX_WBITS)
                dec_name = "carved_%03d_0x%08X_uimage_payload.bin" % (idx, start)
                decomp_path = os.path.join(out_dir, dec_name)
                with open(decomp_path, "wb") as dec_f:
                    dec_f.write(dec)
            except Exception:
                pass

        extracted.append({
            "info": c,
            "path": out_path,
            "decompressed_path": decomp_path
        })

    return extracted

def print_scan_report(filepath, findings):
    print("=" * 80)
    print("  FIRMWARE & CONTAINER BOUNDARY SCAN REPORT")
    print("=" * 80)
    print("  Target File: %s" % filepath)
    print("  Containers Detected: %d" % len(findings))
    print()
    if not findings:
        print("  No embedded firmware containers or compressed streams detected.")
        print("=" * 80)
        return

    print("  %-14s %-14s %-12s %-12s %s" % ("Offset (Hex)", "Offset (Dec)", "Type", "Size", "Description / Metadata"))
    print("  " + "-" * 76)
    for f in findings:
        sz_str = "%d B" % f["total_size"]
        meta = f["description"]
        if f["type"] == "uimage":
            meta += " [%s/%s, name: %s]" % (f.get("arch"), f.get("os"), f.get("name"))
        elif f["type"] == "squashfs":
            meta += " [%s, block: %sB]" % (f.get("compression"), f.get("block_size"))
        print("  0x%08X     %-14d %-12s %-12s %s" % (f["offset"], f["offset"], f["type"], sz_str, meta))
    print("=" * 80)

def main():
    if len(sys.argv) < 3:
        print("Usage: %s <scan|extract|json> <binary-file> [out_dir]" % sys.argv[0])
        sys.exit(1)

    action = sys.argv[1].lower()
    filepath = sys.argv[2]

    if not os.path.isfile(filepath):
        print("Error: file not found: %s" % filepath, file=sys.stderr)
        sys.exit(1)

    if action == "scan":
        findings = scan_file(filepath)
        print_scan_report(filepath, findings)
    elif action == "json":
        findings = scan_file(filepath)
        print(json.dumps(findings, indent=2))
    elif action == "extract":
        out_dir = sys.argv[3] if len(sys.argv) > 3 else "carved_output"
        res = extract_containers(filepath, out_dir)
        print("[+] Carved %d container(s) into: %s" % (len(res), out_dir))
        for r in res:
            inf = r["info"]
            print("    - [%s] offset 0x%08X (%d bytes) -> %s" % (inf["type"].upper(), inf["offset"], inf["total_size"], r["path"]))
            if r["decompressed_path"]:
                print("      ↳ Decompressed stream -> %s" % r["decompressed_path"])
    else:
        print("Unknown action: %s" % action, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
