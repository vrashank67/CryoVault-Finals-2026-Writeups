"""Recover Missing Receipt. Requires Python 3 and cryptography.
Usage: python solve.py EVIDENCE_DIRECTORY OUTPUT_DIRECTORY
Original evidence is read only; SQLite snapshots use a temporary directory.
"""
import argparse
import collections
import contextlib
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3
import struct
import tarfile
import tempfile
import uuid
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def historical_database(evidence):
    raw = bytearray((evidence / 'agent_state.db').read_bytes())
    wal = (evidence / 'agent_state.db-wal').read_bytes()
    size = struct.unpack_from('>I', wal, 8)[0]
    jobs, keys, settings, events = {}, {}, {}, {}
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / 'snapshot.db'
        for off in range(32, len(wal), size + 24):
            page, commit = struct.unpack_from('>II', wal, off)
            data = wal[off + 24:off + 24 + size]
            assert len(data) == size
            end = page * size
            if len(raw) < end:
                raw.extend(bytes(end - len(raw)))
            raw[(page - 1) * size:end] = data
            if not commit:
                continue
            path.write_bytes(raw[:commit * size])
            with contextlib.closing(sqlite3.connect(path)) as db:
                try:
                    recovered_jobs = db.execute('SELECT * FROM jobs').fetchall()
                    recovered_keys = db.execute('SELECT * FROM spool_keys').fetchall()
                    recovered_settings = db.execute('SELECT * FROM settings').fetchall()
                    recovered_events = db.execute('SELECT * FROM activity').fetchall()
                except sqlite3.DatabaseError:
                    # The acquired main DB may contain later checkpointed pages;
                    # early WAL prefixes need not reconstruct a complete old DB.
                    continue
                for row in recovered_jobs:
                    jobs[row[0]] = row
                for row in recovered_keys:
                    keys[row[0]] = row
                settings.update(recovered_settings)
                for row in recovered_events:
                    events[row[0]] = row
    return jobs, keys, settings, events


def capture_connections(path):
    raw = path.read_bytes()
    assert raw[:4] == b'\xd4\xc3\xb2\xa1', 'Expected little-endian microsecond PCAP'
    assert struct.unpack_from('<I', raw, 20)[0] == 1, 'Expected Ethernet'
    connections = collections.OrderedDict()
    off = 24
    while off < len(raw):
        sec, usec, length, original = struct.unpack_from('<IIII', raw, off)
        off += 16
        packet = raw[off:off + length]
        off += length
        if packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        if ip[9] != 6:
            continue
        ip_len = (ip[0] & 15) * 4
        tcp = ip[ip_len:struct.unpack_from('>H', ip, 2)[0]]
        sport, dport, seq = struct.unpack_from('>HHI', tcp)
        if 7447 not in (sport, dport):
            continue
        sender = 'server' if sport == 7447 else 'client'
        client = (ip[16:20], dport) if sender == 'server' else (ip[12:16], sport)
        connection = connections.setdefault(client, {'client': [], 'server': [], 'time': sec + usec / 1e6})
        payload = tcp[(tcp[12] >> 4) * 4:]
        if payload:
            connection[sender].append((seq, payload))
    return list(connections.values())


def linux_reassembly(packets):
    """Receive contiguous bytes; model Linux out-of-order overlap replacement.

    Delivered bytes cannot be overwritten. Queued segments fully covered by a
    new segment are replaced; a new fully contained segment is discarded.
    Partial overlaps are consumed in sequence order when the gap is filled.
    """
    nxt = min(seq for seq, _ in packets)
    queue, output = [], bytearray()
    for seq, data in packets:
        end = seq + len(data)
        if end <= nxt:
            continue
        if seq <= nxt:
            output.extend(data[nxt - seq:])
            nxt = end
        else:
            if any(qs <= seq and qs + len(qd) >= end for qs, qd in queue):
                continue
            queue = [(qs, qd) for qs, qd in queue if not (seq <= qs and end >= qs + len(qd))]
            queue.append((seq, data))
            queue.sort()
        while queue and queue[0][0] <= nxt:
            qs, qd = queue.pop(0)
            qe = qs + len(qd)
            if qe > nxt:
                output.extend(qd[nxt - qs:])
                nxt = qe
    return bytes(output)


def frames(raw):
    off = 0
    while off + 6 <= len(raw):
        assert raw[off:off + 2] == b'\xc7R'
        kind = raw[off + 2]
        length = int.from_bytes(raw[off + 3:off + 6], 'big')
        payload = raw[off + 6:off + 6 + length]
        if len(payload) != length:  # Interrupted final application frame.
            break
        yield kind, payload
        off += 6 + length


def accepted_sessions(connections):
    sessions, tokens = {}, {}
    for number, connection in enumerate(connections):
        outgoing = list(frames(linux_reassembly(connection['client'])))
        incoming = list(frames(linux_reassembly(connection['server'])))
        kind, first = outgoing[0]
        if kind == 1:
            sid = str(uuid.UUID(bytes=first[1:17]))
            session = sessions.setdefault(sid, {'spool': bytearray(), 'connections': []})
            session['length'] = int.from_bytes(first[17:21], 'big')
            hello = next(payload for kind, payload in incoming if kind == 0x81)
            assert hello[0] == 0
            tokens[hello[1:9]] = sid
            session['nonce'] = hello[9:25]
        else:
            assert kind == 2
            sid = tokens[first[:8]]
            session = sessions[sid]
            resume = next(payload for kind, payload in incoming if kind == 0x82)
            assert resume[0] == 0
            assert int.from_bytes(resume[1:5], 'big') == len(session['spool'])
        session['connections'].append(number)
        acks = {int.from_bytes(b[:2], 'big'): (b[2], int.from_bytes(b[3:], 'big'))
                for kind, b in incoming if kind == 0x83}
        for kind, payload in outgoing:
            if kind == 3:
                sequence = int.from_bytes(payload[:2], 'big')
                status, accepted_end = acks.get(sequence, (255, -1))
                if status == 0:
                    offset = int.from_bytes(payload[2:6], 'big')
                    assert offset == len(session['spool'])
                    session['spool'].extend(payload[6:])
                    assert len(session['spool']) == accepted_end
            if kind == 4:
                session['finish_sha256'] = payload.hex()
        for kind, payload in incoming:
            if kind == 0x84:
                session['finish_status'] = payload[0]
                session['receipt'] = payload[1:].hex()
    return sessions


def key_records(path, wanted_id):
    raw = path.read_bytes()
    u32 = lambda b, o: struct.unpack_from('<I', b, o)[0]
    u16 = lambda b, o: struct.unpack_from('<H', b, o)[0]
    sb = raw[1024:2048]
    assert u16(sb, 56) == 0xef53
    blocksize = 1024 << u32(sb, 24)
    per_group, inode_size = u32(sb, 40), u16(sb, 88)
    descriptor_size = max(32, u16(sb, 254))
    descriptor_base = (2 if blocksize == 1024 else 1) * blocksize
    for ino in range(1, u32(sb, 0) + 1):
        group, index = divmod(ino - 1, per_group)
        table = u32(raw, descriptor_base + group * descriptor_size + 8)
        start = table * blocksize + index * inode_size
        inode = raw[start:start + inode_size]
        if u16(inode, 40) != 0xf30a or u16(inode, 46) != 0:
            continue
        generation = u32(inode, 100)
        for entry in range(u16(inode, 42)):
            logical, count, hi, lo = struct.unpack_from('<IHHI', inode, 52 + entry * 12)
            physical = (hi << 32) | lo
            data = raw[physical * blocksize:(physical + (count & 0x7fff)) * blocksize]
            for match in re.finditer(b'CVKEK3\x00\x00', data):
                record = data[match.start():match.start() + 72]
                if len(record) != 72 or record[8:24] != uuid.UUID(wanted_id).bytes:
                    continue
                if hashlib.sha256(record[:56]).digest()[:16] != record[56:]:
                    continue
                mask = hashlib.sha256(b'cvkek3|' + wanted_id.encode() + b'|' + str(generation).encode()).digest()
                yield ino, generation, bytes(a ^ b for a, b in zip(record[24:56], mask))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    jobs, keys, settings, events = historical_database(args.evidence)
    # Acquisition clock lead 402s; an earlier backward correction removed 555s.
    step = next(float(re.search(r'step ([+-]?[0-9.]+)s', row[3])[1])
                for row in events.values() if row[2] == 'timesync')
    lead_before_step = 402 - round(step)
    sessions = accepted_sessions(capture_connections(args.evidence / 'relay.pcap'))
    candidates = []
    for sid, row in jobs.items():
        local = dt.datetime.fromisoformat(row[3])
        utc = local - dt.timedelta(hours=5, minutes=30, seconds=lead_before_step)
        if utc != dt.datetime(2026, 10, 17, 3, 17):
            continue
        session = sessions.get(sid, {})
        print(sid, '03:17 UTC', 'finish status', session.get('finish_status', 'incomplete'))
        if session.get('finish_status') == 0:
            candidates.append((sid, row, session))
    assert len(candidates) == 1
    sid, row, session = candidates[0]
    spool = bytes(session['spool'])
    assert len(spool) == row[5] == session['length']
    digest = hashlib.sha256(spool).hexdigest()
    assert digest == row[6] == session['finish_sha256']
    slot = row[4]
    _, wrapped, kek_id, _ = keys[slot]
    verified = []
    for ino, generation, kek in key_records(args.evidence / 'field-unit.ext4', kek_id):
        effective = HKDF(algorithm=hashes.SHA256(), length=32, salt=session['nonce'],
                         info=f'relay-v3|{sid}|{row[3]}|{slot}'.encode()).derive(kek)
        try:
            key = keywrap.aes_key_unwrap(effective, wrapped)
            assert spool[:4] == b'CV3\0'
            plain = AESGCM(key).decrypt(spool[4:16], spool[16:], f'relay-v3|{sid}'.encode())
        except Exception:
            continue
        verified.append((ino, generation, plain))
    assert len(verified) == 1
    ino, generation, plain = verified[0]
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:gz') as archive:
        manifest = json.load(archive.extractfile('manifest.json'))
        assert manifest['session_id'] == sid
        result = archive.extractfile('custody-result.txt').read()
    flag = re.search(rb'isfcr\{[^}]+\}', result).group().decode()
    report = {'session_id': sid, 'started_utc': '2026-10-17T03:17:00Z',
              'started_local': row[3], 'clock_lead_before_step_seconds': lead_before_step,
              'connections': session['connections'], 'accepted_length': len(spool),
              'spool_sha256': digest, 'relay_finish_status': session['finish_status'],
              'relay_receipt_hex': session['receipt'], 'key_inode': ino,
              'inode_generation': generation, 'aes_kw_integrity': 'passed',
              'aes_gcm_authentication': 'passed', 'export_length': len(plain),
              'export_sha256': hashlib.sha256(plain).hexdigest(), 'manifest': manifest,
              'flag': flag, 'submission': 'not submitted'}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'accepted-spool.cv3').write_bytes(spool)
    (args.output / 'export.tar.gz').write_bytes(plain)
    (args.output / 'custody-result.txt').write_bytes(result)
    (args.output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
