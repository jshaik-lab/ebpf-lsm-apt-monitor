"""Diagnose why ValidCallSiteMap.build() returns 0 call sites for nginx."""
from __future__ import annotations
import sys
sys.path.insert(0, "src/python")

from elftools.elf.elffile import ELFFile

BIN = "/usr/sbin/nginx"
SENSITIVE = {"connect", "write", "send", "sendto", "sendmsg",
             "execve", "execveat", "mmap", "mmap2"}

with open(BIN, "rb") as f:
    elf = ELFFile(f)
    print(f"arch = {elf['e_machine']}")
    text = elf.get_section_by_name(".text")
    plt  = elf.get_section_by_name(".plt")
    rela = (elf.get_section_by_name(".rela.plt") or
            elf.get_section_by_name(".rel.plt"))
    dyn  = elf.get_section_by_name(".dynsym")
    print(f".text base=0x{text['sh_addr']:x} size={text['sh_size']} bytes")
    print(f".plt  base=0x{plt['sh_addr']:x} size={plt['sh_size']} bytes")
    print(f".rela.plt entries: {sum(1 for _ in rela.iter_relocations())}")
    print(f".dynsym  entries: {dyn.num_symbols()}")

    # All sensitive symbols present in dynsym
    print("\nSensitive symbols in dynsym:")
    found = {}
    for i in range(dyn.num_symbols()):
        s = dyn.get_symbol(i)
        if s.name in SENSITIVE:
            found[s.name] = i
            print(f"  dyn[{i}] = {s.name!r}")
    print(f"  total in dynsym: {len(found)}")

    # Walk .rela.plt and see which dynsym entries it cites
    print("\n.rela.plt → dynsym citations (first 30):")
    relocs = sorted(rela.iter_relocations(), key=lambda r: r["r_offset"])
    sensitive_relocs = []
    for i, r in enumerate(relocs):
        sym_idx = r["r_info_sym"]
        sym = dyn.get_symbol(sym_idx)
        if i < 30:
            mark = " ✓ SENSITIVE" if sym.name in SENSITIVE else ""
            print(f"  rel[{i}] offset=0x{r['r_offset']:x} sym=dyn[{sym_idx}]={sym.name!r}{mark}")
        if sym.name in SENSITIVE:
            sensitive_relocs.append((i, sym.name, r["r_offset"]))
    print(f"\nSensitive in rela.plt: {len(sensitive_relocs)}")
    for i, name, off in sensitive_relocs[:10]:
        plt_addr = plt["sh_addr"] + 16 * (i + 1)
        print(f"  rel[{i}] sym={name} got_offset=0x{off:x} → plt_va=0x{plt_addr:x}")

    # Confirm by disassembling: walk first 200 bytes of .text and look at calls
    print("\nDisassembly probe (first call instructions in .text):")
    text_bytes = text.data()
    text_base = text["sh_addr"]
    import capstone
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    seen_calls = 0
    for ins in cs.disasm(text_bytes, text_base):
        if ins.mnemonic == "call":
            seen_calls += 1
            if seen_calls <= 5:
                print(f"  0x{ins.address:x}: call {ins.op_str}")
        if seen_calls > 200:
            break
    print(f"  total call instructions scanned: {seen_calls}")

    # Build PLT map manually + count call sites for connect
    print("\nManual PLT map build:")
    plt_base = plt["sh_addr"]
    plt_map = {}
    for i, r in enumerate(relocs):
        sym = dyn.get_symbol(r["r_info_sym"])
        if sym.name in SENSITIVE:
            plt_map[sym.name] = plt_base + 16 * (i + 1)
    print(f"  plt_map size: {len(plt_map)}")
    for sym, va in plt_map.items():
        print(f"    {sym}: plt_va = 0x{va:x}")

    # Count call sites targeting plt entries
    print("\nCalls into PLT range (manual scan):")
    if plt_map:
        plt_range_lo = min(plt_map.values()) - 32
        plt_range_hi = max(plt_map.values()) + 32
        cs2 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        site_count = {s: 0 for s in plt_map}
        for ins in cs2.disasm(text_bytes, text_base):
            if ins.mnemonic != "call":
                continue
            try:
                target = int(ins.op_str.replace("qword ptr ", ""), 16)
            except ValueError:
                continue
            if not (plt_range_lo <= target <= plt_range_hi):
                continue
            for sym, plt_va in plt_map.items():
                if abs(target - plt_va) < 32:
                    site_count[sym] += 1
                    break
        total = sum(site_count.values())
        print(f"  total calls into sensitive PLTs: {total}")
        for sym, n in site_count.items():
            print(f"    {sym}: {n}")
