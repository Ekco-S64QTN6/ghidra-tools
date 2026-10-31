#!/usr/bin/env python3
"""
firmware_carver.py — Deep boundary detection and container carving pipeline for embedded firmware.

Detects, carves, and metadata-analyzes embedded firmware containers:
- SquashFS v3/v4 (little-/big-endian, structurally validated superblocks; opaque contents)
- CRAMFS v2 (little-/big-endian, bounded superblock and root-inode validation; opaque contents)
- U-Boot uImage (OS, Arch, Type, Compression, Load Address, Entry Point, Name)
- JFFS2 nodes
- GZIP compressed kernel/stage streams
- Embedded ELF binaries
"""

import os
import sys
import struct
import zlib
import json
import time
import math
import mmap
from dataclasses import dataclass


CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class CarveLimits:
    """Fail-closed resource budgets for scanning and extraction."""

    max_depth: int = 3
    max_files: int = 128
    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_compression_ratio: float = 100.0
    timeout_seconds: float = 30.0

    def __post_init__(self):
        if self.max_depth < 0:
            raise ValueError("GHIDRA_CARVE_MAX_DEPTH must be >= 0")
        if self.max_files < 1:
            raise ValueError("GHIDRA_CARVE_MAX_FILES must be >= 1")
        if self.max_file_bytes < 1:
            raise ValueError("GHIDRA_CARVE_MAX_FILE_BYTES must be >= 1")
        if self.max_total_bytes < 1:
            raise ValueError("GHIDRA_CARVE_MAX_TOTAL_BYTES must be >= 1")
        if not math.isfinite(self.max_compression_ratio) or self.max_compression_ratio < 1:
            raise ValueError("GHIDRA_CARVE_MAX_COMPRESSION_RATIO must be finite and >= 1")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("GHIDRA_CARVE_TIMEOUT_SECONDS must be finite and > 0")

    @classmethod
    def from_env(cls):
        """Load validated, bounded limits from GHIDRA_CARVE_* variables."""
        defaults = cls()
        values = {}
        settings = (
            ("max_depth", "GHIDRA_CARVE_MAX_DEPTH", int),
            ("max_files", "GHIDRA_CARVE_MAX_FILES", int),
            ("max_file_bytes", "GHIDRA_CARVE_MAX_FILE_BYTES", int),
            ("max_total_bytes", "GHIDRA_CARVE_MAX_TOTAL_BYTES", int),
            ("max_compression_ratio", "GHIDRA_CARVE_MAX_COMPRESSION_RATIO", float),
            ("timeout_seconds", "GHIDRA_CARVE_TIMEOUT_SECONDS", float),
        )
        for field, env_name, converter in settings:
            raw = os.environ.get(env_name)
            try:
                values[field] = converter(raw) if raw is not None else getattr(defaults, field)
            except (TypeError, ValueError):
                raise ValueError("%s must be a valid %s" % (env_name, converter.__name__))
        return cls(**values)


class CarveBudgetExceeded(RuntimeError):
    """An extraction or scan budget was exhausted."""


class UnsafeCompressedStream(RuntimeError):
    """A compressed stream is corrupt or violates its expansion limits."""


class ExtractionBudget:
    def __init__(self, limits, deadline):
        self.limits = limits
        self.deadline = deadline
        self.files_written = 0
        self.bytes_written = 0

    def check_time(self):
        if time.monotonic() > self.deadline:
            raise CarveBudgetExceeded("wall-time budget exceeded")

    def check_slot(self):
        self.check_time()
        if self.files_written >= self.limits.max_files:
            raise CarveBudgetExceeded("maximum extracted file count reached")

    def check_size(self, size):
        self.check_time()
        if size < 0 or size > self.limits.max_file_bytes:
            raise CarveBudgetExceeded(
                "file size %d exceeds the per-file limit of %d bytes"
                % (size, self.limits.max_file_bytes)
            )
        if self.bytes_written + size > self.limits.max_total_bytes:
            raise CarveBudgetExceeded(
                "total output would exceed the %d-byte extraction budget"
                % self.limits.max_total_bytes
            )

    def commit_file(self, size):
        self.files_written += 1
        self.bytes_written += size


def _check_deadline(deadline):
    if deadline is not None and time.monotonic() > deadline:
        raise CarveBudgetExceeded("wall-time budget exceeded")


def parse_uimage(data, offset, deadline=None):
    if offset < 0 or len(data) - offset < 64:
        return None
    hdr = data[offset:offset + 64]
    magic, hcrc, tstamp, dsize, load, ep, dcrc, os_type, arch, img_type, comp = struct.unpack(">IIIIIIIBBBB", hdr[:32])
    if magic != 0x27051956:
        return None

    # The uImage data size is untrusted. Reject a container whose declared
    # payload does not fit entirely after the 64-byte header.
    available_payload = len(data) - offset - 64
    if dsize > available_payload:
        return None

    # U-Boot calculates ih_hcrc over the complete 64-byte header after
    # setting ih_hcrc to zero. Keep this byte-for-byte compatible.
    header_for_crc = bytearray(hdr)
    struct.pack_into(">I", header_for_crc, 4, 0)
    calculated_hcrc = zlib.crc32(header_for_crc) & 0xFFFFFFFF
    if hcrc != calculated_hcrc:
        return None

    # ih_dcrc covers exactly ih_size bytes after the header. Process the
    # payload in bounded chunks so scanning a large image never copies it all.
    calculated_dcrc = 0
    payload_cursor = offset + 64
    payload_end = payload_cursor + dsize
    while payload_cursor < payload_end:
        _check_deadline(deadline)
        chunk_end = min(payload_cursor + CHUNK_BYTES, payload_end)
        calculated_dcrc = zlib.crc32(data[payload_cursor:chunk_end], calculated_dcrc)
        payload_cursor = chunk_end
    calculated_dcrc &= 0xFFFFFFFF
    if dcrc != calculated_dcrc:
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
        "header_crc32": "0x%08X" % hcrc,
        "data_crc32": "0x%08X" % dcrc,
        "os": os_map.get(os_type, "os_" + str(os_type)),
        "arch": arch_map.get(arch, "arch_" + str(arch)),
        "compression": comp_map.get(comp, "comp_" + str(comp)),
        "name": name,
        "load_address": "0x%08X" % load,
        "entry_point": "0x%08X" % ep,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(tstamp)) if tstamp > 0 else "unknown"
    }

def parse_squashfs(data, offset):
    """Validate a SquashFS v3/v4 superblock without parsing filesystem contents."""
    if offset < 0 or len(data) - offset < 96:
        return None

    magic_bytes = data[offset:offset + 4]
    if magic_bytes == b"hsqs":
        endian = "<"
        endian_name = "little"
    elif magic_bytes == b"sqsh":
        endian = ">"
        endian_name = "big"
    else:
        return None

    try:
        (
            inodes, mkfs_time, block_size, fragments, comp, block_log,
            flags, no_ids, s_major, s_minor,
        ) = struct.unpack_from(endian + "IIIIHHHHHH", data, offset + 4)
        root_inode = struct.unpack_from(endian + "Q", data, offset + 32)[0]
        bytes_used = struct.unpack_from(endian + "Q", data, offset + 40)[0]

        supported_version = (
            (s_major == 3 and s_minor <= 1)
            or (s_major == 4 and s_minor == 0)
        )
        if not supported_version or inodes == 0:
            return None
        if block_size < 4096 or block_size > (1 << 20):
            return None
        if block_log < 12 or block_log > 20 or block_size != (1 << block_log):
            return None
        if (root_inode & 0xFFFF) > 8192:
            return None
        if bytes_used < 96 or bytes_used > len(data) - offset:
            return None

        comp_map = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
        return {
            "type": "squashfs",
            "description": "SquashFS v%d.%d Filesystem" % (s_major, s_minor),
            "offset": offset,
            "total_size": bytes_used,
            "endian": endian_name,
            "compression": comp_map.get(comp, "id_" + str(comp)),
            "block_size": block_size,
            "inodes": inodes,
            "root_inode_offset": root_inode & 0xFFFF,
            "created": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(mkfs_time)) if mkfs_time > 0 else "unknown",
        }
    except (struct.error, OverflowError, ValueError):
        return None


def parse_cramfs(data, offset):
    """Validate a bounded CRAMFS v2 superblock; leave its contents opaque."""
    superblock_size = 76
    if offset < 0 or len(data) - offset < superblock_size:
        return None

    magic_bytes = data[offset:offset + 4]
    if magic_bytes == b"\x45\x3d\xcd\x28":
        endian = "<"
        endian_name = "little"
    elif magic_bytes == b"\x28\xcd\x3d\x45":
        endian = ">"
        endian_name = "big"
    else:
        return None

    try:
        size, flags, future = struct.unpack_from(endian + "III", data, offset + 4)
        signature = data[offset + 16:offset + 32]
        crc, edition, blocks, files = struct.unpack_from(endian + "IIII", data, offset + 32)
        name = data[offset + 48:offset + 64].split(b"\x00", 1)[0].decode("latin-1", errors="replace")
        root_mode = struct.unpack_from(endian + "H", data, offset + 64)[0]
        root_word = struct.unpack_from(endian + "I", data, offset + 72)[0]

        fsid_version_2 = 0x00000001
        shifted_root_offset = 0x00000400
        wrong_signature = 0x00000200
        supported_flags = 0x00000FFF
        if not (flags & fsid_version_2):
            return None
        if flags & ~supported_flags:
            return None
        if signature != b"Compressed ROMFS" and not (flags & wrong_signature):
            return None
        if size < superblock_size or size > len(data) - offset:
            return None
        if (root_mode & 0o170000) != 0o040000:
            return None

        if endian == "<":
            root_offset = ((root_word >> 6) & 0x03FFFFFF) << 2
        else:
            root_offset = (root_word & 0x03FFFFFF) << 2
        if root_offset:
            if root_offset >= size:
                return None
            if not (flags & shifted_root_offset) and root_offset not in (
                superblock_size, 512 + superblock_size
            ):
                return None

        return {
            "type": "cramfs",
            "description": "CRAMFS Filesystem",
            "offset": offset,
            "total_size": size,
            "name": name,
            "endian": endian_name,
            "flags": "0x%08X" % flags,
            "files": files,
            "blocks": blocks,
            "crc32": "0x%08X" % crc,
            "root_offset": root_offset,
        }
    except (struct.error, OverflowError, ValueError):
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

def parse_gzip(data, offset, limits=None, deadline=None):
    """Validate one GZIP stream with bounded input, output, and elapsed time."""
    if offset < 0 or len(data) - offset < 18:
        return None
    if data[offset:offset + 3] != b"\x1f\x8b\x08":
        return None

    limits = limits or CarveLimits()
    max_stream_bytes = min(len(data) - offset, limits.max_file_bytes)
    max_output_bytes = min(limits.max_file_bytes, limits.max_total_bytes)
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    cursor = offset
    output_size = 0

    try:
        while cursor - offset < max_stream_bytes:
            _check_deadline(deadline)
            end = min(cursor + CHUNK_BYTES, offset + max_stream_bytes)
            chunk = data[cursor:end]
            cursor = end
            pending = chunk

            while pending:
                allowance = max_output_bytes - output_size
                if allowance < 0:
                    return None
                before = len(pending)
                output = decompressor.decompress(
                    pending, min(CHUNK_BYTES, allowance + 1)
                )
                output_size += len(output)
                if output_size > max_output_bytes:
                    return None
                pending = decompressor.unconsumed_tail
                if decompressor.eof:
                    consumed = cursor - offset - len(decompressor.unused_data)
                    if consumed <= 10 or output_size == 0:
                        return None
                    if output_size > consumed * limits.max_compression_ratio:
                        return None
                    return {
                        "type": "gzip",
                        "description": "GZIP Compressed Stream / Kernel",
                        "offset": offset,
                        "total_size": consumed,
                        "uncompressed_size_sample": min(output_size, 4096),
                        "uncompressed_size": output_size,
                        "compression_ratio": round(output_size / consumed, 2),
                    }
                if pending and len(pending) == before and not output:
                    return None
    except (zlib.error, ValueError):
        return None
    return None


def _open_mapped(path):
    """Map a non-empty input read-only so large firmware files are not copied."""
    handle = open(path, "rb")
    try:
        size = os.fstat(handle.fileno()).st_size
        if size == 0:
            handle.close()
            return None, None
        mapped = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        return handle, mapped
    except Exception:
        handle.close()
        raise


def _jffs2_crc32(data, crc=0):
    """Linux crc32_le() convention used by JFFS2 (no initial/final XOR)."""
    return (zlib.crc32(data, crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _jffs2_pad4(length):
    return (length + 3) & ~3


def parse_jffs2(data, offset, deadline=None):
    """Validate a JFFS2 raw inode or directory-entry node before carving.

    Only INODE (0xE002) and DIRENT (0xE001) are supported. Other JFFS2
    families are ignored rather than accepted on a common header alone.
    """
    available = len(data) - offset
    if offset < 0 or available < 12:
        return None

    magic_bytes = data[offset:offset + 2]
    if magic_bytes == b"\x85\x19":
        endian = "<"
    elif magic_bytes == b"\x19\x85":
        endian = ">"
    else:
        return None

    try:
        magic, nodetype, totlen, header_crc = struct.unpack_from(
            endian + "HHII", data, offset
        )
    except struct.error:
        return None

    if magic != 0x1985 or nodetype not in (0xE001, 0xE002):
        return None
    if totlen < 12 or totlen > min(65536, available):
        return None

    padded_length = _jffs2_pad4(totlen)
    if padded_length > available:
        return None

    calculated_header_crc = _jffs2_crc32(data[offset:offset + 8])
    if header_crc != calculated_header_crc:
        return None

    if nodetype == 0xE001:  # JFFS2_NODETYPE_DIRENT
        fixed_size = 40
        if totlen < fixed_size:
            return None
        name_size = data[offset + 28]
        if name_size > 254 or _jffs2_pad4(fixed_size + name_size) != padded_length:
            return None

        node_crc = struct.unpack_from(endian + "I", data, offset + 32)[0]
        name_crc = struct.unpack_from(endian + "I", data, offset + 36)[0]
        calculated_node_crc = _jffs2_crc32(data[offset:offset + 32])
        if node_crc != calculated_node_crc:
            return None

        raw_name = data[offset + fixed_size:offset + fixed_size + name_size]
        name = raw_name.split(b"\x00", 1)[0]
        calculated_name_crc = _jffs2_crc32(name)
        if name_crc != calculated_name_crc:
            return None

        pino, version, ino = struct.unpack_from(endian + "III", data, offset + 12)
        return {
            "type": "jffs2",
            "description": "JFFS2 directory-entry node",
            "node_kind": "dirent",
            "offset": offset,
            "total_size": padded_length,
            "node_size": totlen,
            "inode": ino,
            "parent_inode": pino,
            "version": version,
            "name": name.decode("latin-1", errors="replace"),
            "header_crc32": "0x%08X" % header_crc,
            "node_crc32": "0x%08X" % node_crc,
            "name_crc32": "0x%08X" % name_crc,
        }

    fixed_size = 68  # JFFS2 raw inode
    if totlen < fixed_size:
        return None
    compressed_size, decompressed_size = struct.unpack_from(
        endian + "II", data, offset + 48
    )
    if _jffs2_pad4(fixed_size + compressed_size) != padded_length:
        return None

    data_crc = struct.unpack_from(endian + "I", data, offset + 60)[0]
    node_crc = struct.unpack_from(endian + "I", data, offset + 64)[0]
    calculated_node_crc = _jffs2_crc32(data[offset:offset + 60])
    if node_crc != calculated_node_crc:
        return None

    calculated_data_crc = 0
    payload_cursor = offset + fixed_size
    payload_end = payload_cursor + compressed_size
    while payload_cursor < payload_end:
        _check_deadline(deadline)
        chunk_end = min(payload_cursor + CHUNK_BYTES, payload_end)
        calculated_data_crc = _jffs2_crc32(
            data[payload_cursor:chunk_end], calculated_data_crc
        )
        payload_cursor = chunk_end
    if data_crc != calculated_data_crc:
        return None

    inode, version, mode = struct.unpack_from(endian + "III", data, offset + 12)
    return {
        "type": "jffs2",
        "description": "JFFS2 inode node",
        "node_kind": "inode",
        "offset": offset,
        "total_size": padded_length,
        "node_size": totlen,
        "inode": inode,
        "version": version,
        "mode": "0%o" % mode,
        "compressed_size": compressed_size,
        "decompressed_size": decompressed_size,
        "compression": data[offset + 56],
        "header_crc32": "0x%08X" % header_crc,
        "node_crc32": "0x%08X" % node_crc,
        "data_crc32": "0x%08X" % data_crc,
    }


def scan_file(filepath, limits=None, deadline=None):
    limits = limits or CarveLimits.from_env()
    deadline = deadline if deadline is not None else time.monotonic() + limits.timeout_seconds
    handle, data = _open_mapped(filepath)
    if data is None:
        return []

    try:
        findings = []
        i = 0
        n = len(data)

        while i < n - 16:
            if (i & 0xFFF) == 0:
                _check_deadline(deadline)
            chunk = data[i:i + 4]

            # 1. U-Boot uImage
            if chunk == b"\x27\x05\x19\x56":
                res = parse_uimage(data, i, deadline)
                if res:
                    findings.append(res)
                    if len(findings) >= limits.max_files:
                        break
                    i += max(64, res["total_size"])
                    continue
                if n - i >= 64:
                    declared_size = struct.unpack_from(">I", data, i + 12)[0]
                    available_payload = n - i - 64
                    if declared_size > available_payload:
                        print(
                            "[WARN] Ignoring truncated uImage at 0x%X: "
                            "header declares %d payload bytes, only %d remain."
                            % (i, declared_size, available_payload),
                            file=sys.stderr,
                        )
                    else:
                        print(
                            "[WARN] Ignoring invalid uImage at 0x%X: "
                            "header or payload CRC-32 mismatch."
                            % i,
                            file=sys.stderr,
                        )

            # 2. SquashFS
            if chunk in (b"hsqs", b"sqsh"):
                res = parse_squashfs(data, i)
                if res:
                    findings.append(res)
                    if len(findings) >= limits.max_files:
                        break
                    i += max(96, res["total_size"])
                    continue

            # 3. CRAMFS
            if chunk in (b"\x45\x3d\xcd\x28", b"\x28\xcd\x3d\x45"):
                res = parse_cramfs(data, i)
                if res:
                    findings.append(res)
                    if len(findings) >= limits.max_files:
                        break
                    i += max(64, res["total_size"])
                    continue

            # 4. Embedded ELF
            if chunk == b"\x7fELF" and i > 0:
                res = parse_elf(data, i)
                if res:
                    findings.append(res)
                    if len(findings) >= limits.max_files:
                        break
                    i += max(52, res["total_size"])
                    continue

            # 5. GZIP
            if data[i:i + 3] == b"\x1f\x8b\x08":
                res = parse_gzip(data, i, limits, deadline)
                if res:
                    findings.append(res)
                    if len(findings) >= limits.max_files:
                        break
                    i += max(10, res["total_size"])
                    continue

                                    # 6. JFFS2 INODE/DIRENT nodes with type-specific CRC validation
            if data[i:i + 2] in (b"\x85\x19", b"\x19\x85"):
                res = parse_jffs2(data, i, deadline)
                if res:
                    findings.append(res)
                    if len(findings) >= limits.max_files:
                        break
                    i += max(12, res["total_size"])
                    continue

            i += 1

        return findings
    finally:
        data.close()
        handle.close()


def _temporary_output_path(path):
    return path + ".part"


def _copy_region(source_path, offset, length, output_path, budget):
    """Copy one validated input region in chunks and atomically publish it."""
    budget.check_slot()
    budget.check_size(length)
    temporary_path = _temporary_output_path(output_path)
    written = 0
    try:
        with open(source_path, "rb") as source:
            source_size = os.fstat(source.fileno()).st_size
            if offset < 0 or length < 0 or offset + length > source_size:
                raise UnsafeCompressedStream("container bounds changed after scanning")
            source.seek(offset)
            with open(temporary_path, "wb") as destination:
                remaining = length
                while remaining:
                    budget.check_time()
                    chunk = source.read(min(CHUNK_BYTES, remaining))
                    if not chunk:
                        raise UnsafeCompressedStream("input ended during extraction")
                    destination.write(chunk)
                    written += len(chunk)
                    remaining -= len(chunk)
        os.replace(temporary_path, output_path)
        budget.commit_file(written)
        return output_path
    except Exception:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise


def _decompress_gzip_region(source_path, offset, length, output_path, budget):
    """Stream a GZIP region to disk while enforcing expansion and time limits."""
    budget.check_slot()
    if length <= 0:
        raise UnsafeCompressedStream("empty GZIP payload")
    max_output = min(
        budget.limits.max_file_bytes,
        budget.limits.max_total_bytes - budget.bytes_written,
        int(length * budget.limits.max_compression_ratio),
    )
    if max_output <= 0:
        raise CarveBudgetExceeded("no output budget remains for GZIP expansion")

    temporary_path = _temporary_output_path(output_path)
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output_size = 0
    try:
        with open(source_path, "rb") as source:
            source_size = os.fstat(source.fileno()).st_size
            if offset < 0 or length < 0 or offset + length > source_size:
                raise UnsafeCompressedStream("GZIP payload bounds are invalid")
            source.seek(offset)
            remaining = length
            with open(temporary_path, "wb") as destination:
                while remaining:
                    budget.check_time()
                    chunk = source.read(min(CHUNK_BYTES, remaining))
                    if not chunk:
                        raise UnsafeCompressedStream("truncated GZIP input")
                    remaining -= len(chunk)
                    pending = chunk
                    while pending:
                        allowance = max_output - output_size
                        if allowance < 0:
                            raise UnsafeCompressedStream("GZIP output exceeds its expansion budget")
                        before = len(pending)
                        output = decompressor.decompress(
                            pending, min(CHUNK_BYTES, allowance + 1)
                        )
                        output_size += len(output)
                        if output_size > max_output:
                            raise UnsafeCompressedStream("GZIP output exceeds its expansion budget")
                        if output:
                            destination.write(output)
                        pending = decompressor.unconsumed_tail
                        if decompressor.eof:
                            if decompressor.unused_data:
                                raise UnsafeCompressedStream("trailing bytes follow the GZIP member")
                            break
                        if pending and len(pending) == before and not output:
                            raise UnsafeCompressedStream("GZIP decoder made no progress")
                    if decompressor.eof and remaining:
                        raise UnsafeCompressedStream("trailing bytes follow the GZIP member")

        if not decompressor.eof or output_size == 0:
            raise UnsafeCompressedStream("incomplete or empty GZIP member")
        if output_size > length * budget.limits.max_compression_ratio:
            raise UnsafeCompressedStream("GZIP expansion ratio exceeds its configured limit")
        os.replace(temporary_path, output_path)
        budget.commit_file(output_size)
        return output_path
    except Exception:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise


def extract_containers(filepath, out_dir, limits=None):
    """Recursively carve recognized containers under strict resource budgets."""
    limits = limits or CarveLimits.from_env()
    deadline = time.monotonic() + limits.timeout_seconds
    budget = ExtractionBudget(limits, deadline)
    os.makedirs(out_dir, exist_ok=True)

    queue = [(os.path.abspath(filepath), 0, None)]
    visited = set()
    extracted = []
    next_index = 0
    stop_reason = None

    while queue:
        budget.check_time()
        source_path, depth, parent_name = queue.pop(0)
        real_source = os.path.realpath(source_path)
        if real_source in visited:
            continue
        visited.add(real_source)

        try:
            findings = scan_file(source_path, limits=limits, deadline=deadline)
        except CarveBudgetExceeded as error:
            stop_reason = str(error)
            break

        for finding in findings:
            try:
                budget.check_time()
                start = finding["offset"]
                size = finding["total_size"]
                c_type = finding["type"]
                ext = {
                    "squashfs": "squashfs",
                    "uimage": "uimage",
                    "elf": "elf",
                    "gzip": "gz",
                    "cramfs": "cramfs",
                }.get(c_type, "bin")

                out_name = "carved_%04d_d%d_0x%08X_%s.%s" % (
                    next_index, depth, start, c_type, ext
                )
                next_index += 1
                out_path = os.path.join(out_dir, out_name)
                _copy_region(source_path, start, size, out_path, budget)

                info = dict(finding)
                info["depth"] = depth
                info["source"] = os.path.basename(source_path)
                if parent_name:
                    info["parent"] = parent_name

                decomp_path = None
                gzip_region = None
                if c_type == "gzip":
                    gzip_region = (start, size)
                    dec_suffix = "decompressed"
                elif c_type == "uimage" and finding.get("compression") == "gzip":
                    gzip_region = (start + finding.get("header_size", 64),
                                   finding.get("payload_size", 0))
                    dec_suffix = "uimage_payload"

                if gzip_region:
                    dec_name = "carved_%04d_d%d_0x%08X_%s.bin" % (
                        next_index, depth, start, dec_suffix
                    )
                    next_index += 1
                    candidate_path = os.path.join(out_dir, dec_name)
                    try:
                        decomp_path = _decompress_gzip_region(
                            source_path, gzip_region[0], gzip_region[1],
                            candidate_path, budget
                        )
                        if depth < limits.max_depth:
                            queue.append((decomp_path, depth + 1, out_name))
                        else:
                            print(
                                "[WARN] Recursion depth limit %d reached at %s"
                                % (limits.max_depth, out_name),
                                file=sys.stderr,
                            )
                    except UnsafeCompressedStream as error:
                        print(
                            "[WARN] Skipping unsafe GZIP payload at %s: %s"
                            % (out_name, error),
                            file=sys.stderr,
                        )
                    except CarveBudgetExceeded as error:
                        stop_reason = str(error)
                        extracted.append({
                            "info": info,
                            "path": out_path,
                            "decompressed_path": None,
                        })
                        break

                extracted.append({
                    "info": info,
                    "path": out_path,
                    "decompressed_path": decomp_path,
                })
            except CarveBudgetExceeded as error:
                stop_reason = str(error)
                break
            except (OSError, UnsafeCompressedStream) as error:
                print("[WARN] Skipping extraction at %s: %s" % (source_path, error), file=sys.stderr)

        if stop_reason:
            break

    if stop_reason:
        print("[WARN] Firmware extraction stopped: %s" % stop_reason, file=sys.stderr)
    print(
        "[INFO] Extraction budget: %d file(s), %d byte(s) written (limits: %d files, %d bytes)"
        % (
            budget.files_written, budget.bytes_written,
            limits.max_files, limits.max_total_bytes,
        ),
        file=sys.stderr,
    )
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
    try:
        limits = CarveLimits.from_env()
    except ValueError as error:
        print("[ERROR] Invalid firmware carve limits: %s" % error, file=sys.stderr)
        sys.exit(2)

    if not os.path.isfile(filepath):
        print("Error: file not found: %s" % filepath, file=sys.stderr)
        sys.exit(1)

    if action == "scan":
        findings = scan_file(filepath, limits=limits)
        print_scan_report(filepath, findings)
    elif action == "json":
        findings = scan_file(filepath, limits=limits)
        print(json.dumps(findings, indent=2))
    elif action == "extract":
        out_dir = sys.argv[3] if len(sys.argv) > 3 else "carved_output"
        res = extract_containers(filepath, out_dir, limits=limits)
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
    try:
        main()
    except CarveBudgetExceeded as error:
        print("[ERROR] Firmware carving stopped: %s" % error, file=sys.stderr)
        sys.exit(2)
