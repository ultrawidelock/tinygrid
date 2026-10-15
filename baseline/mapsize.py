#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Flash and RAM per input object, from a GNU ld map of a non-LTO build.

Usage: mapsize.py zephyr.map [--group REGEX ...] [--top N] [--objects REGEX]

Flash counts every allocated input section whose output section sits below
0x20000000, plus the load image of RAM sections that have a load address
(.data). RAM counts every input section at 0x20000000 and above. Fill bytes
are reported apart, attributed to nobody.
"""
import argparse
import re
import sys
from collections import defaultdict

RAM_BASE = 0x20000000
SKIP = re.compile(r'^\.(debug|comment|ARM\.attributes|rel|stab|note|gnu)')
HDR = re.compile(r'^(\S+)?\s*0x([0-9a-f]+)\s+0x([0-9a-f]+)(?:\s+load address 0x([0-9a-f]+))?\s*$')
INP = re.compile(r'^\s+(\S+)?\s*0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(\S.*)$')


def parse(path):
    flash, ram = defaultdict(int), defaultdict(int)
    fill_flash = fill_ram = 0
    out_name, out_ram, out_load = None, False, False
    pending_out = None
    started = False
    with open(path, errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            if not started:
                started = line.startswith('Linker script and memory map')
                continue
            if line and not line[0].isspace():
                m = HDR.match(line)
                if m and m.group(1):
                    out_name = m.group(1)
                    out_ram = int(m.group(2), 16) >= RAM_BASE
                    out_load = m.group(4) is not None
                    pending_out = None
                elif re.match(r'^\S+$', line):
                    pending_out = line
                continue
            if pending_out is not None:
                m = HDR.match(line.strip())
                if m and not m.group(1):
                    out_name = pending_out
                    out_ram = int(m.group(2), 16) >= RAM_BASE
                    out_load = m.group(4) is not None
                    pending_out = None
                    continue
                pending_out = None
            if out_name is None or SKIP.match(out_name):
                continue
            s = line.strip()
            if s.startswith('*fill*'):
                m = re.search(r'0x([0-9a-f]+)\s+0x([0-9a-f]+)', s)
                if m:
                    n = int(m.group(2), 16)
                    if out_ram:
                        fill_ram += n
                        if out_load:
                            fill_flash += n
                    else:
                        fill_flash += n
                continue
            m = INP.match(line)
            if not m:
                continue
            size = int(m.group(3), 16)
            obj = m.group(4).strip()
            if size == 0 or obj.startswith('load address'):
                continue
            if out_ram:
                ram[obj] += size
                if out_load:
                    flash[obj] += size
            else:
                flash[obj] += size
    return flash, ram, fill_flash, fill_ram


def short(obj):
    m = re.match(r'(?:.*/)?([^/(]+)\((.+)\)$', obj)
    if m:
        return m.group(1), m.group(2)
    return obj.rsplit('/', 1)[-1], obj.rsplit('/', 1)[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('map')
    ap.add_argument('--group', action='append', default=[],
                    help='NAME=REGEX on the full object path; first match wins')
    ap.add_argument('--objects', help='list objects whose path matches REGEX')
    ap.add_argument('--top', type=int, default=0)
    ap.add_argument('--archives', action='store_true',
                    help='group by archive (or loose object) name')
    a = ap.parse_args()
    flash, ram, ff, fr = parse(a.map)
    groups = [g.split('=', 1) for g in a.group]
    if a.archives:
        groups = [(n, '(^|/)' + re.escape(n) + r'(\(|$)') for n in
                  sorted({short(o)[0] for o in set(flash) | set(ram)})]
    tot = defaultdict(lambda: [0, 0])
    for obj in set(flash) | set(ram):
        key = next((n for n, rx in groups if re.search(rx, obj)), 'other')
        tot[key][0] += flash.get(obj, 0)
        tot[key][1] += ram.get(obj, 0)
    print(f'{"group":<28}{"flash_B":>10}{"ram_B":>10}')
    for k, (fl, rm) in sorted(tot.items(), key=lambda kv: -kv[1][0]):
        print(f'{k:<28}{fl:>10}{rm:>10}')
    print(f'{"(fill)":<28}{ff:>10}{fr:>10}')
    print(f'{"TOTAL":<28}{sum(flash.values()) + ff:>10}{sum(ram.values()) + fr:>10}')
    if a.objects:
        rows = defaultdict(lambda: [0, 0])
        for obj in set(flash) | set(ram):
            if re.search(a.objects, obj):
                k = short(obj)[1]
                rows[k][0] += flash.get(obj, 0)
                rows[k][1] += ram.get(obj, 0)
        rows = sorted(rows.items(), key=lambda kv: -kv[1][0])
        if a.top:
            rows = rows[:a.top]
        print()
        print(f'{"object":<44}{"flash_B":>10}{"ram_B":>10}')
        for k, (fl, rm) in rows:
            print(f'{k:<44}{fl:>10}{rm:>10}')


if __name__ == '__main__':
    sys.exit(main())
