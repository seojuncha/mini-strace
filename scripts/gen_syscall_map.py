#!/usr/bin/env python3
"""
Generate a C syscall-name mapper from Linux kernel syscall *.tbl files.

Example:
  ./gen_syscall_map.py --tbl linux/arch/x86/entry/syscalls/syscall_64.tbl --out syscall_map_x86_64.c
  ./gen_syscall_map.py --tbl linux/arch/x86/entry/syscalls/syscall_32.tbl --out syscall_map_i386.c
  ./gen_syscall_map.py --tbl linux/arch/arm/tools/syscall.tbl --out syscall_map_arm.c
"""

from __future__ import annotations
import argparse
import re
from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional


@dataclass(frozen=True)
class Syscall:
  nr: int
  abi: str
  name: str
  entry: str


def parse_tbl_line(line: str) -> Optional[Syscall]:
  # Strip comments (kernel tbl often uses #)
  line = line.split("#", 1)[0].strip()
  if not line:
    return None

  # Columns are whitespace separated; allow multiple spaces/tabs.
  cols = re.split(r"\s+", line)
  if len(cols) < 4:
    # Some tables may have fewer cols; ignore safely.
    return None

  # Expected: nr abi name entry [compat...]
  nr_s, abi, name, entry = cols[0], cols[1], cols[2], cols[3]

  # nr should be int
  if not re.fullmatch(r"\d+", nr_s):
    return None

  nr = int(nr_s)

  # Some tables include "unused" or reserved placeholders; ignore them.
  if name in ("unused", "reserved"):
    return None

  # Some include "sys_" prefixes in entry; not needed. We only need name.
  return Syscall(nr=nr, abi=abi, name=name, entry=entry)


def load_syscalls(tbl_path: str,
                  abi_filter: Optional[List[str]] = None,
                  drop_names: Optional[List[str]] = None) -> List[Syscall]:
  syscalls: List[Syscall] = []
  drop = set(drop_names or [])
  abi_keep = set(abi_filter or [])

  with open(tbl_path, "r", encoding="utf-8", errors="replace") as f:
    for raw in f:
      sc = parse_tbl_line(raw)
      if sc is None:
          continue
      if abi_keep and sc.abi not in abi_keep:
          continue
      if sc.name in drop:
          continue
      syscalls.append(sc)

  # De-dup by syscall number: if duplicates exist, prefer the first occurrence.
  seen: set[int] = set()
  uniq: List[Syscall] = []
  for sc in sorted(syscalls, key=lambda s: s.nr):
    if sc.nr in seen:
        continue
    seen.add(sc.nr)
    uniq.append(sc)
  return uniq


def gen_c_switch(syscalls: List[Syscall],
                 func_name: str = "syscall_name",
                 default_name: str = "unknown",
                 include_header: bool = True) -> str:
  lines: List[str] = []
  if include_header:
    lines += [
        "/* AUTO-GENERATED FILE. DO NOT EDIT. */",
        "/* Generated from Linux kernel syscall table (*.tbl). */",
        "",
        "#include <stddef.h>",
        "#include \"syscall_map.h\"",
        "",
    ]

  lines += [
      f"const char *{func_name}(unsigned long nr)",
      "{",
      "  switch (nr) {",
  ]

  for sc in syscalls:
    # Use numeric case to avoid relying on __NR_* / SYS_* defines.
    lines.append(f"    case {sc.nr}: return \"{sc.name}\";")

  lines += [
      f"    default: return \"{default_name}\";",
      "  }",
      "}",
      "",
  ]
  return "\n".join(lines)


def gen_c_array(syscalls: List[Syscall],
                array_name: str = "syscall_names",
                func_name: str = "syscall_name",
                default_name: str = "unknown",
                include_header: bool = True) -> str:
  """
  Optional alternative: dense array [0..max] => name or NULL.
  Faster than switch for large tables, but bigger static data.
  """
  max_nr = max((sc.nr for sc in syscalls), default=0)
  by_nr: Dict[int, str] = {sc.nr: sc.name for sc in syscalls}

  lines: List[str] = []
  if include_header:
    lines += [
        "/* AUTO-GENERATED FILE. DO NOT EDIT. */",
        "/* Generated from Linux kernel syscall table (*.tbl). */",
        "",
        "#include <stddef.h>",
        "#include \"syscall_map.h\"",
        "",
    ]

  lines += [
      f"const char *{array_name}[{max_nr + 1}] = {{"
  ]
  for i in range(max_nr + 1):
    name = by_nr.get(i)
    if name is None:
        lines.append("\tNULL,")
    else:
        lines.append(f"\t\"{name}\",")
  lines += [
      "};",
      "",
      f"const char *{func_name}(unsigned long nr)",
      "{",
      f"\tif (nr <= {max_nr} && {array_name}[nr] != NULL)",
      f"\t\treturn {array_name}[nr];",
      f"\treturn \"{default_name}\";",
      "}",
      "",
  ]
  return "\n".join(lines)


def main() -> None:
  ap = argparse.ArgumentParser()
  ap.add_argument("--tbl", required=True, help="Path to Linux kernel syscall table (*.tbl)")
  ap.add_argument("--out", required=True, help="Output C file path")
  ap.add_argument("--func", default="syscall_name", help="Generated function name")
  ap.add_argument("--mode", choices=["switch", "array"], default="switch",
                  help="Codegen mode: switch or array")
  ap.add_argument("--abi", action="append", default=None,
                  help="ABI filter (repeatable). Example: --abi common --abi 64")
  ap.add_argument("--drop", action="append", default=None,
                  help="Drop syscall name (repeatable). Example: --drop ni_syscall")
  args = ap.parse_args()

  syscalls = load_syscalls(args.tbl, abi_filter=args.abi, drop_names=args.drop)

  if args.mode == "switch":
    c = gen_c_switch(syscalls, func_name=args.func)
  else:
    c = gen_c_array(syscalls, func_name=args.func)

  with open(args.out, "w", encoding="utf-8") as f:
    f.write(c)

  print(f"[ok] generated {args.out} from {args.tbl} ({len(syscalls)} syscalls)")


if __name__ == "__main__":
  main()
