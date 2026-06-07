"""ValidCallSiteMap — Static binary analysis for PCABP.

Scans an ELF binary (e.g. /usr/sbin/nginx) and builds a Bloom filter of
every valid return address from CALL-to-connect()/write()/send() in .text.

At runtime: if a kernel event's instruction pointer is NOT in this bloom
filter, the syscall was invoked by code outside the binary — heap/stack
shellcode — triggering the PCABP static violation flag.

Usage (offline, one-time at agent startup):
    csm = ValidCallSiteMap.build("/usr/sbin/nginx")
    csm.save("/var/lib/sentinel/nginx_call_sites.pkl")

Usage (online, per event):
    is_valid, delta = csm.check(event.ip, load_addr=process_map_base)
"""
from __future__ import annotations

import hashlib
import math
import pickle
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Set


# ── Bloom filter ─────────────────────────────────────────────────────────────

class _Bloom:
    """Deterministic k-hash Bloom filter backed by a bytearray."""

    def __init__(self, capacity: int = 200_000, fpr: float = 0.001):
        m = max(8, int(-capacity * math.log(fpr) / (math.log(2) ** 2)))
        k = max(1, int((m / capacity) * math.log(2)))
        self._m   = m
        self._k   = k
        self._buf = bytearray((m + 7) // 8)
        self._n   = 0

    def _bits(self, v: int):
        raw = hashlib.sha256(struct.pack("<Q", v & 0xFFFF_FFFF_FFFF_FFFF)).digest()
        for i in range(self._k):
            seed = struct.pack("<I", i)
            h = int.from_bytes(
                hashlib.sha256(raw + seed).digest()[:4], "little"
            ) % self._m
            yield h

    def add(self, v: int) -> None:
        for b in self._bits(v):
            self._buf[b >> 3] |= 1 << (b & 7)
        self._n += 1

    def __contains__(self, v: int) -> bool:
        return all((self._buf[b >> 3] >> (b & 7)) & 1 for b in self._bits(v))

    @property
    def fpr(self) -> float:
        exp = -self._k * self._n / self._m
        return (1 - math.exp(exp)) ** self._k if self._n else 0.0


# ── Call-site map ─────────────────────────────────────────────────────────────

@dataclass
class ValidCallSiteMap:
    """Bloom filter of valid syscall call sites extracted from an ELF binary.

    Attributes
    ----------
    binary_path   : path scanned
    text_base     : virtual address of .text section (0 for PIE before reloc)
    text_size     : byte length of .text
    call_sites    : {symbol_name: set of return-address offsets in .text}
    bloom         : Bloom filter over all return addresses (static offsets)
    """
    binary_path: str = ""
    text_base:   int = 0
    text_size:   int = 0
    call_sites:  Dict[str, Set[int]] = field(default_factory=dict)
    bloom:       _Bloom              = field(default_factory=_Bloom)
    # Cached union of all call_sites values — built once at build() time.
    # Avoids O(n) set union on every IP miss in check().
    _all_sites:  frozenset           = field(default_factory=frozenset)

    _SENSITIVE = frozenset({
        "connect", "write", "send", "sendto", "sendmsg",
        "execve", "execveat", "mmap", "mmap2",
    })

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def build(cls, binary_path: str) -> "ValidCallSiteMap":
        """Parse binary and populate bloom filter. Returns self."""
        obj = cls(binary_path=binary_path)
        obj.call_sites = {s: set() for s in cls._SENSITIVE}
        try:
            obj._parse_elf()
        except ImportError:
            # pyelftools not installed → fall back to empty map (PCABP disabled)
            pass
        for sites in obj.call_sites.values():
            for addr in sites:
                obj.bloom.add(addr)
        obj._all_sites = frozenset().union(*obj.call_sites.values())
        total = sum(len(s) for s in obj.call_sites.values())
        _log(f"[CallSiteMap] {Path(binary_path).name}: "
             f"text=0x{obj.text_base:x}+{obj.text_size//1024}KB "
             f"call_sites={total} bloom_fpr={obj.bloom.fpr:.5f}")
        return obj

    def _parse_elf(self) -> None:
        from elftools.elf.elffile import ELFFile  # type: ignore[import]

        with open(self.binary_path, "rb") as fh:
            elf = ELFFile(fh)
            arch = elf["e_machine"]  # EM_X86_64, EM_AARCH64, EM_386, …
            self._find_text(elf)
            plt_map = self._build_plt_map(elf, arch)
            text_sec = elf.get_section_by_name(".text")
            if text_sec:
                self._scan(text_sec.data(), text_sec["sh_addr"], plt_map, arch)

    def _find_text(self, elf) -> None:
        sec = elf.get_section_by_name(".text")
        if sec:
            self.text_base = sec["sh_addr"]
            self.text_size = sec["sh_size"]

    def _build_plt_map(self, elf, arch: str) -> Dict[str, int]:
        """Return {symbol: PLT entry vaddr} by matching .rela.plt → .dynsym.

        PLT stub size by arch:
          x86_64  : 16 bytes  (JMP [RIP+GOT] + PUSH idx + JMP plt0)
          aarch64 : 16 bytes  (ADRP + LDR + ADD + BR)
          i386    : 16 bytes
        """
        plt_map: Dict[str, int] = {}
        plt_sec  = elf.get_section_by_name(".plt")
        rela_sec = (elf.get_section_by_name(".rela.plt") or
                    elf.get_section_by_name(".rel.plt"))
        dynsym   = elf.get_section_by_name(".dynsym")
        if not all([plt_sec, rela_sec, dynsym]):
            return plt_map
        plt_base  = plt_sec["sh_addr"]
        plt_entry = 16  # 16 bytes for x86_64, aarch64, i386
        relocs = sorted(rela_sec.iter_relocations(), key=lambda r: r["r_offset"])
        for i, reloc in enumerate(relocs):
            sym = dynsym.get_symbol(reloc["r_info_sym"])
            if sym and sym.name in self._SENSITIVE:
                plt_map[sym.name] = plt_base + plt_entry * (i + 1)
        return plt_map

    def _scan(self, text: bytes, vma: int, plt_map: Dict[str, int],
              arch: str = "EM_X86_64") -> None:
        """Disassemble .text and collect return addresses of calls into PLT.

        Supports x86_64 (CALL rel32) and AArch64 (BL #imm).
        Falls back to raw E8 byte scan on x86 if capstone is unavailable.
        """
        if not plt_map:
            return
        try:
            import capstone  # type: ignore[import]

            if arch == "EM_AARCH64":
                cs      = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                mnemonic_match = "bl"
                insn_size = 4  # ARM64: all instructions are 4 bytes
                def _target(op_str: str) -> int:
                    # Capstone ARM64 format: '#0x12345' or '0x12345'
                    return int(op_str.lstrip("#"), 16)
            else:
                # x86_64 or i386
                mode = (capstone.CS_MODE_64 if arch == "EM_X86_64"
                        else capstone.CS_MODE_32)
                cs      = capstone.Cs(capstone.CS_ARCH_X86, mode)
                mnemonic_match = "call"
                insn_size = None  # variable on x86
                def _target(op_str: str) -> int:
                    return int(op_str.replace("qword ptr ", ""), 16)

            plt_range_lo = min(plt_map.values()) - 32
            plt_range_hi = max(plt_map.values()) + 32

            for insn in cs.disasm(text, vma):
                if insn.mnemonic != mnemonic_match:
                    continue
                try:
                    target = _target(insn.op_str)
                except (ValueError, IndexError):
                    continue
                if not (plt_range_lo <= target <= plt_range_hi):
                    continue
                ret = insn.address + (insn_size if insn_size else insn.size)
                for sym, plt_va in plt_map.items():
                    if abs(target - plt_va) < 32:
                        self.call_sites[sym].add(ret)

        except ImportError:
            # capstone not installed → raw E8 byte scan (x86 only)
            i = 0
            while i < len(text) - 5:
                if text[i] == 0xE8:
                    rel = struct.unpack_from("<i", text, i + 1)[0]
                    tgt = vma + i + 5 + rel
                    ret = vma + i + 5
                    for sym, plt_va in plt_map.items():
                        if abs(tgt - plt_va) < 32:
                            self.call_sites[sym].add(ret)
                i += 1

    # ── Runtime API (hot path) ────────────────────────────────────────────────

    def check(self, ip: int, load_addr: int = 0) -> tuple[bool, int]:
        """Check whether `ip` is a valid call site.

        Parameters
        ----------
        ip        : instruction pointer captured by eBPF
        load_addr : ASLR base from /proc/<pid>/maps (0 = non-PIE or unknown)

        Returns
        -------
        (is_valid, offset_delta)
            is_valid     : True = IP is in bloom filter (in-binary call)
            offset_delta : distance from nearest valid site (0 = exact match)
        """
        if ip == 0:
            return True, 0  # no IP captured → can't judge → pass through

        static_addr = ip - load_addr if load_addr else ip
        if static_addr in self.bloom:
            return True, 0

        # Compute minimum distance for AI encoder feature
        delta = min((abs(static_addr - s) for s in self._all_sites), default=0)
        return False, delta

    def region(self, ip: int, load_addr: int = 0) -> str:
        """Classify IP region: TEXT | HEAP | STACK | MMAP | UNKNOWN."""
        if ip == 0:
            return "UNKNOWN"
        adj = ip - load_addr if load_addr else ip
        if self.text_base and self.text_base <= adj < self.text_base + self.text_size:
            return "TEXT"
        if 0x0060_0000_0000_0000 <= ip <= 0x007f_ffff_ffff_ffff:
            return "HEAP_MMAP"
        return "UNKNOWN"

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: str) -> None:
        Path(path).write_bytes(pickle.dumps(self))
        _log(f"[CallSiteMap] saved → {path}")

    @classmethod
    def load(cls, path: str) -> "ValidCallSiteMap":
        return pickle.loads(Path(path).read_bytes())


def _log(msg: str) -> None:
    import logging
    logging.getLogger("sentinel.pcabp").info(msg)
