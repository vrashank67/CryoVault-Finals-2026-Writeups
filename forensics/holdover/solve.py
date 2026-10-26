#!/usr/bin/env python3
"""Reconstruct frost-n07; optionally run the supplied escrow opener.
Usage: python solve.py INPUT_DIRECTORY [--open]
Needs gmpy2 only for the optional, several-minute escrow computation.
"""
import argparse
import collections
import csv
from fractions import Fraction
from pathlib import Path
import struct
import subprocess
import sys


def crc32c(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value ^ 0xffffffff


def checked(page, offset):
    expected = struct.unpack_from('<I', page, offset)[0]
    assert crc32c(page[:offset] + bytes(4) + page[offset+4:]) == expected


def reconstruct(root):
    data = (root / 'n07.aonv').read_bytes()
    assert len(data) == 1048576 and data[:8] == b'AONVAULT'
    rev, size, count, used, _, total = struct.unpack_from('<HHIIII', data, 8)
    assert (rev, size, count) == (2, 256, 4096)
    checked(data[:256], 20)
    spares, lanes, lane_size, tail = struct.unpack_from('<IHHI', data, 28)
    tick_num, ppm_q16 = struct.unpack_from('<Ii', data, 40)
    tail_data = data[tail*size:(tail+1)*size]
    assert tail_data[:4] == b'AOVT'
    checked(tail_data, 12)
    remap_count, reset_count = struct.unpack_from('<I', tail_data, 8)[0], struct.unpack_from('<I', tail_data, 16)[0]
    assert remap_count == spares
    remaps = [struct.unpack_from('<HHHH', tail_data, 32+8*i) for i in range(remap_count)]
    mapping = {p: p for p in range(1, 1 + lanes*lane_size)}
    for retired, spare, lane, reserved in remaps:
        origins = [p for p, current in mapping.items() if current == retired]
        assert len(origins) == 1 and (origins[0]-1)//lane_size == lane
        assert data[retired*size:(retired+1)*size] == b'\xff'*size
        mapping[origins[0]] = spare
    pages = []
    for physical in mapping.values():
        raw = data[physical*size:(physical+1)*size]
        assert raw[:4] == b'AOVP'
        checked(raw, 12)
        fill = struct.unpack_from('<I', raw, 8)[0]
        lane = struct.unpack_from('<H', raw, 16)[0]
        seq, base = struct.unpack_from('<IQ', raw, 20)
        assert fill <= 7 and lane < lanes
        records = []
        for slot in range(fill):
            kind, op, sensor, dtick, setpoint, state, ctx, payload, rsv = struct.unpack_from('<BBHIiIIQI', raw, 32+32*slot)
            records.append(dict(page=physical, slot=slot, lane=lane, seq=seq,
                                tick=base+dtick, kind=kind, op=op, state=state))
        assert all(a['tick'] <= b['tick'] for a,b in zip(records, records[1:]))
        pages.append(dict(page=physical, lane=lane, seq=seq, base=base, records=records))
    assert sum(len(p['records']) for p in pages) == total
    assert sum(32 + 32*len(p['records']) for p in pages) == used
    # Learn the lane cycle from complete page-opening rounds in the long intact epoch.
    groups = collections.defaultdict(list)
    for p in pages:
        if p['base'] > 10000:
            groups[p['seq']].append(p)
    cycles = collections.Counter(tuple(p['lane'] for p in sorted(g, key=lambda p:p['base']))
                                 for g in groups.values() if len(g) == lanes)
    cycle, frequency = cycles.most_common(1)[0]
    rank = {lane: index for index,lane in enumerate(cycle)}
    pages.sort(key=lambda p:(p['seq'],rank[p['lane']]))
    assert all(b['lane'] == cycle[(rank[a['lane']]+1)%lanes] for a,b in zip(pages,pages[1:]))
    records = [r for p in pages for r in p['records']]
    resets = [r for r in records if r['kind'] == 0x11]
    assert len(resets) == reset_count
    # Every backwards AON counter jump starts with an explicit AONRST record.
    drops = [(a,b) for a,b in zip(records,records[1:]) if b['tick'] < a['tick']]
    assert len(drops) == reset_count and all(b['kind'] == 0x11 for a,b in drops)
    marks = [r for r in records if r['kind'] == 0x2a]
    assert len(marks) == 24
    mark_string = ''.join(chr(r['op']) for r in marks)
    first_mark = records.index(marks[0])
    latch = [r for r in records[:first_mark] if r['kind']==9 and r['op']==1][-1]
    manufacture_period = (Fraction(24000) + Fraction(tick_num,1000000)) / (24000000 * (1+Fraction(ppm_q16,65536*1000000)))
    # Since 2.2.0 TICK is an external row-bus minute pulse. Measure the
    # running clock, rather than assuming its manufacture calibration persists.
    ticks = [r['tick'] for r in records if r['kind'] == 1]
    assert all(60003 <= b-a <= 60004 for a,b in zip(ticks,ticks[1:]))
    span = ticks[-1]-ticks[0]
    pulse_seconds = 60*(len(ticks)-1)
    period = Fraction(pulse_seconds,span)
    seconds = latch['tick']*period
    lower = Fraction(latch['tick']*pulse_seconds,span+2)
    upper = Fraction(latch['tick']*pulse_seconds,span-2)
    hundredths = (seconds*100).numerator // (seconds*100).denominator
    assert (lower*100).numerator//(lower*100).denominator == hundredths
    assert (upper*100).numerator//(upper*100).denominator == hundredths
    print(f'Manufacture-only uptime (rejected): {float(latch["tick"]*manufacture_period):.9f}')
    print(f'Pulse-derived uptime range with 2-tick endpoint variation: {float(lower):.9f} .. {float(upper):.9f}')
    code = f'FL-{mark_string}-{hundredths//100}.{hundredths%100:02d}'
    print(f'CRC and layout verified: {len(pages)} pages, {total} records, {used} live bytes')
    print(f'Lane cycle: {cycle}; supported by {frequency} complete historical rounds')
    print(f'AON resets: {reset_count}; marks: {mark_string}')
    print(f'Latch: page {latch["page"]}, slot {latch["slot"]}, tick {latch["tick"]}')
    print(f'Pulse-derived tick period estimate: {period} seconds; uptime: {float(seconds):.9f} seconds')
    print(code)
    return code, marks


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('directory',type=Path)
    ap.add_argument('--open',action='store_true')
    args=ap.parse_args()
    code, marks = reconstruct(args.directory)
    with Path(__file__).with_name('marks.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['order','page','slot','lane','seq','tick','character'])
        writer.writeheader()
        for order,r in enumerate(marks,1):
            writer.writerow(dict(order=order, **{k:r[k] for k in ['page','slot','lane','seq','tick']},character=chr(r['op'])))
    if args.open:
        subprocess.run([sys.executable,str(args.directory/'escrow.py'),str(args.directory/'release.lock'),code],check=True)

if __name__=='__main__':
    main()
