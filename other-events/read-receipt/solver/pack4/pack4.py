#!/usr/bin/env python3
"""Pack/4 (RRPCK4) sparse filesystem and canonical R4SP export engine.

Implements the "Pack 4" section of the RR-3 interoperability note, revision 4.0.

Public API
----------
parse_container(data) -> Container
parse_view(data) -> View
emit_container(container) -> bytes
emit_view(view) -> bytes
build_container(atoms, namespaces, nodes) -> bytes
build_view(namespace_id, handle, offset, length) -> bytes
resolve_view(container_bytes, view_bytes) -> bytes      # canonical R4SP export
Resolver(container).canonical_export(view) -> bytes
Resolver(container).resolve_view_segments(view) -> tuple[Segment, ...]
group_runs(segments, requested_length) -> tuple[Run, ...]
iter_export(requested_length, segments) -> Iterator[bytes]
write_export(fileobj, requested_length, segments)

CLI
---
    python pack4.py container.bin view.bin [--out FILE] [--quiet]

writes the canonical export to stdout (or --out FILE) and a human readable
summary to stderr.

Design notes
------------
* Resolution is range based.  A node is never expanded; only the requested
  window is evaluated, and holes are represented by (start, length) without a
  data payload.  A 1 TiB hole therefore costs one segment.
* Nodes are represented as a list of half-open segments in ascending,
  contiguous, view-relative coordinates.  ``Segment.data is None`` means the
  segment reads as zeroes; ``Segment.allocated`` says whether those zeroes are
  stored (allocated zero / literal zero byte) or a hole.
* Operators are painted into an interval map *before* any source is resolved,
  so references that are completely overwritten by later operators are never
  dereferenced ("only dependencies of final requested coordinates are live").
* Namespace binding maps are computed once per namespace and are immutable
  snapshots; a reference always resolves in the namespace named by the
  reference, never in the caller's or the newest namespace.
* Resolution is memoized per (node id, offset, length).  Exact re-entry of a
  key that is still being computed is genuine infinite recursion and raises
  CycleError.
"""

from __future__ import annotations

import bisect
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

__all__ = [
    "Pack4Error",
    "ParseError",
    "ResolutionError",
    "CycleError",
    "MAGIC",
    "VIEW_MAGIC",
    "EXPORT_MAGIC",
    "ZERO_NAMESPACE",
    "ZERO_HANDLE",
    "make_handle",
    "handle_parts",
    "Atom",
    "Namespace",
    "Node",
    "Reference",
    "View",
    "OpBind",
    "OpRemove",
    "OpExchange",
    "OpLiteral",
    "OpClone",
    "OpHole",
    "OpZero",
    "Container",
    "Segment",
    "Run",
    "parse_container",
    "parse_view",
    "emit_container",
    "emit_view",
    "build_container",
    "build_view",
    "group_runs",
    "iter_export",
    "write_export",
    "Resolver",
    "resolve_view",
]

MAGIC = b"RRPCK4\0\0"
VIEW_MAGIC = b"R4VW"
EXPORT_MAGIC = b"R4SP"

ZERO_NAMESPACE = bytes(16)
ZERO_HANDLE = bytes(6)

MAX_U64 = (1 << 64) - 1

_ZERO_BLOCK = bytes(1 << 20)

# Operation tags.
NS_OP_BIND = 0x11
NS_OP_REMOVE = 0x29
NS_OP_EXCHANGE = 0x3B
NODE_OP_LITERAL = 0x17
NODE_OP_CLONE = 0x35
NODE_OP_HOLE = 0x52
NODE_OP_ZERO = 0x68


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class Pack4Error(Exception):
    """Base class for all pack/4 errors."""


class ParseError(Pack4Error):
    """Malformed container or view bytes."""


class ResolutionError(Pack4Error):
    """A structurally valid container could not be resolved."""


class CycleError(ResolutionError):
    """A coordinate depends on itself; the request cannot terminate."""


# ---------------------------------------------------------------------------
# little helpers
# ---------------------------------------------------------------------------


def make_handle(inode: int, incarnation: int) -> bytes:
    """Build the 6-byte handle key: inode:u32 little-endian + incarnation:u16."""
    if not (0 <= inode <= 0xFFFFFFFF):
        raise ValueError("inode does not fit in u32")
    if not (0 <= incarnation <= 0xFFFF):
        raise ValueError("incarnation does not fit in u16")
    return struct.pack("<IH", inode, incarnation)


def handle_parts(handle: bytes) -> Tuple[int, int]:
    if len(handle) != 6:
        raise ValueError("handle must be 6 bytes")
    return struct.unpack("<IH", handle)


def _as_bytes(value, what: str) -> bytes:
    try:
        out = bytes(value)
    except TypeError:
        raise Pack4Error(f"{what} is not bytes-like") from None
    return out


def _need_len(value: bytes, n: int, what: str) -> bytes:
    if len(value) != n:
        raise Pack4Error(f"{what} must be {n} bytes, got {len(value)}")
    return value


def _encode_varint(value: int) -> bytes:
    if not (0 <= value <= MAX_U64):
        raise Pack4Error(f"varint out of range: {value}")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _decode_varint(data: bytes, pos: int, end: int) -> Tuple[int, int]:
    """Decode an unsigned LEB128 integer of at most 64 bits.

    Ten-byte encodings are accepted only when they cannot overflow 64 bits
    (the tenth byte must be 0x00 or 0x01 and must terminate the integer).
    """
    result = 0
    shift = 0
    for index in range(10):
        if pos >= end:
            raise ParseError("truncated varint")
        byte = data[pos]
        pos += 1
        if index == 9:
            if byte & 0x80:
                raise ParseError("varint exceeds 10 bytes / 64 bits")
            if byte > 0x01:
                raise ParseError("varint exceeds 64 bits")
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            return result, pos
    raise ParseError("varint exceeds 10 bytes / 64 bits")


class _Reader:
    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, pos: int = 0, end: Optional[int] = None):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    def take(self, n: int, what: str = "field") -> bytes:
        if n < 0:
            raise ParseError(f"negative length for {what}")
        if self.pos + n > self.end:
            raise ParseError(
                f"truncated {what} at offset {self.pos}: need {n} bytes, "
                f"{self.end - self.pos} available"
            )
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self, what: str = "u8") -> int:
        return self.take(1, what)[0]

    def u32(self, what: str = "u32") -> int:
        return struct.unpack("<I", self.take(4, what))[0]

    def var(self, what: str = "varint") -> int:
        value, self.pos = _decode_varint(self.data, self.pos, self.end)
        return value

    def at_end(self) -> bool:
        return self.pos == self.end


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Atom:
    id: bytes
    data: bytes


@dataclass(frozen=True, slots=True)
class Reference:
    """namespace id[16] + handle[6]."""

    namespace_id: bytes
    handle: bytes

    def to_bytes(self) -> bytes:
        return self.namespace_id + self.handle


@dataclass(frozen=True, slots=True)
class OpBind:
    handle: bytes
    node_id: bytes


@dataclass(frozen=True, slots=True)
class OpRemove:
    handle: bytes


@dataclass(frozen=True, slots=True)
class OpExchange:
    first: bytes
    second: bytes


@dataclass(frozen=True, slots=True)
class OpLiteral:
    dest: int
    length: int
    atom_id: bytes
    source_offset: int


@dataclass(frozen=True, slots=True)
class OpClone:
    dest: int
    length: int
    reference: Reference
    source_offset: int


@dataclass(frozen=True, slots=True)
class OpHole:
    dest: int
    length: int


@dataclass(frozen=True, slots=True)
class OpZero:
    dest: int
    length: int


@dataclass(frozen=True, slots=True)
class Namespace:
    id: bytes
    base: bytes
    ops: Tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class Node:
    id: bytes
    logical_size: int
    base: Reference
    ops: Tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class View:
    namespace_id: bytes
    handle: bytes
    offset: int
    length: int


@dataclass
class Container:
    atoms: List[Atom]
    namespaces: List[Namespace]
    nodes: List[Node]
    atom_map: Dict[bytes, Atom] = field(init=False, repr=False)
    namespace_map: Dict[bytes, Namespace] = field(init=False, repr=False)
    node_map: Dict[bytes, Node] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # IDs within one table should be unique; if they are not, the last
        # record wins for resolution while emission preserves every record.
        self.atom_map = {a.id: a for a in self.atoms}
        self.namespace_map = {n.id: n for n in self.namespaces}
        self.node_map = {n.id: n for n in self.nodes}


@dataclass(frozen=True, slots=True)
class Segment:
    """A half-open piece of resolved content, relative to the request start."""

    start: int
    length: int
    allocated: bool
    data: Optional[bytes]  # bytes for allocated payload; None = zero fill / hole

    @property
    def end(self) -> int:
        return self.start + self.length


@dataclass(frozen=True, slots=True)
class Run:
    """A maximal run of one allocation state in the canonical export."""

    allocated: bool
    start: int
    length: int
    segments: Tuple[Segment, ...]

    @property
    def end(self) -> int:
        return self.start + self.length


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def parse_container(data: bytes, *, allow_trailing: bool = False) -> Container:
    data = _as_bytes(data, "container")
    reader = _Reader(data)

    magic = reader.take(8, "container magic")
    if magic != MAGIC:
        raise ParseError(f"bad container magic: {magic!r}")
    atom_count = reader.u32("atom count")
    namespace_count = reader.u32("namespace count")
    node_count = reader.u32("node count")

    atoms: List[Atom] = []
    for index in range(atom_count):
        atom_id = reader.take(16, f"atom[{index}] id")
        length = reader.var(f"atom[{index}] length")
        payload = reader.take(length, f"atom[{index}] data")
        atoms.append(Atom(atom_id, payload))

    namespaces: List[Namespace] = []
    for index in range(namespace_count):
        ns_id = reader.take(16, f"namespace[{index}] id")
        base = reader.take(16, f"namespace[{index}] base")
        op_count = reader.var(f"namespace[{index}] op count")
        ops: List[object] = []
        for op_index in range(op_count):
            label = f"namespace[{index}] op[{op_index}]"
            tag = reader.u8(f"{label} tag")
            if tag == NS_OP_BIND:
                ops.append(
                    OpBind(
                        reader.take(6, f"{label} handle"),
                        reader.take(16, f"{label} node id"),
                    )
                )
            elif tag == NS_OP_REMOVE:
                ops.append(OpRemove(reader.take(6, f"{label} handle")))
            elif tag == NS_OP_EXCHANGE:
                first = reader.take(6, f"{label} first handle")
                second = reader.take(6, f"{label} second handle")
                ops.append(OpExchange(first, second))
            else:
                raise ParseError(f"{label}: unknown namespace opcode 0x{tag:02x}")
        namespaces.append(Namespace(ns_id, base, tuple(ops)))

    nodes: List[Node] = []
    for index in range(node_count):
        node_id = reader.take(16, f"node[{index}] id")
        logical_size = reader.var(f"node[{index}] logical size")
        base = Reference(
            reader.take(16, f"node[{index}] base namespace"),
            reader.take(6, f"node[{index}] base handle"),
        )
        op_count = reader.var(f"node[{index}] op count")
        ops = []
        for op_index in range(op_count):
            label = f"node[{index}] op[{op_index}]"
            tag = reader.u8(f"{label} tag")
            if tag == NODE_OP_LITERAL:
                ops.append(
                    OpLiteral(
                        reader.var(f"{label} destination"),
                        reader.var(f"{label} length"),
                        reader.take(16, f"{label} atom id"),
                        reader.var(f"{label} source offset"),
                    )
                )
            elif tag == NODE_OP_CLONE:
                ops.append(
                    OpClone(
                        reader.var(f"{label} destination"),
                        reader.var(f"{label} length"),
                        Reference(
                            reader.take(16, f"{label} reference namespace"),
                            reader.take(6, f"{label} reference handle"),
                        ),
                        reader.var(f"{label} source offset"),
                    )
                )
            elif tag == NODE_OP_HOLE:
                ops.append(
                    OpHole(
                        reader.var(f"{label} destination"),
                        reader.var(f"{label} length"),
                    )
                )
            elif tag == NODE_OP_ZERO:
                ops.append(
                    OpZero(
                        reader.var(f"{label} destination"),
                        reader.var(f"{label} length"),
                    )
                )
            else:
                raise ParseError(f"{label}: unknown node opcode 0x{tag:02x}")
        nodes.append(Node(node_id, logical_size, base, tuple(ops)))

    if not allow_trailing and not reader.at_end():
        raise ParseError(
            f"{reader.end - reader.pos} trailing bytes after node table"
        )
    return Container(atoms, namespaces, nodes)


def _pick_endian(endian: str) -> str:
    if endian in ("le", "little", "<"):
        return "<"
    if endian in ("be", "big", ">"):
        return ">"
    raise Pack4Error(f"unsupported byte order: {endian!r}")


def parse_view(
    data: bytes, *, allow_trailing: bool = False, endian: str = "<"
) -> View:
    """Parse a view.

    The RR-3 note says all fixed-width integers are little-endian unless
    specified otherwise, and only the canonical export is specified as
    big-endian, so the default is little-endian.  ``endian`` is an escape
    hatch for checking an alternative reading of the two u64 fields.
    """
    format_char = _pick_endian(endian)
    data = _as_bytes(data, "view")
    reader = _Reader(data)
    magic = reader.take(4, "view magic")
    if magic != VIEW_MAGIC:
        raise ParseError(f"bad view magic: {magic!r}")
    namespace_id = reader.take(16, "view namespace")
    handle = reader.take(6, "view handle")
    offset, length = struct.unpack(
        format_char + "QQ", reader.take(16, "view offset/length")
    )
    if not allow_trailing and not reader.at_end():
        raise ParseError(f"{reader.end - reader.pos} trailing bytes after view")
    return View(namespace_id, handle, offset, length)


# ---------------------------------------------------------------------------
# emission (used for tests, round-trips and tooling)
# ---------------------------------------------------------------------------


def _check_atom(atom: Atom) -> None:
    _need_len(atom.id, 16, "atom id")
    if not isinstance(atom.data, (bytes, bytearray)):
        raise Pack4Error("atom data must be bytes")


def _emit_reference(ref: Reference) -> bytes:
    _need_len(ref.namespace_id, 16, "reference namespace")
    _need_len(ref.handle, 6, "reference handle")
    return ref.namespace_id + ref.handle


def _emit_namespace_op(op: object) -> bytes:
    if isinstance(op, OpBind):
        _need_len(op.handle, 6, "bind handle")
        _need_len(op.node_id, 16, "bind node id")
        return bytes([NS_OP_BIND]) + op.handle + op.node_id
    if isinstance(op, OpRemove):
        _need_len(op.handle, 6, "remove handle")
        return bytes([NS_OP_REMOVE]) + op.handle
    if isinstance(op, OpExchange):
        _need_len(op.first, 6, "exchange first handle")
        _need_len(op.second, 6, "exchange second handle")
        return bytes([NS_OP_EXCHANGE]) + op.first + op.second
    raise Pack4Error(f"not a namespace operation: {op!r}")


def _emit_node_op(op: object) -> bytes:
    if isinstance(op, OpLiteral):
        _need_len(op.atom_id, 16, "literal atom id")
        return (
            bytes([NODE_OP_LITERAL])
            + _encode_varint(op.dest)
            + _encode_varint(op.length)
            + op.atom_id
            + _encode_varint(op.source_offset)
        )
    if isinstance(op, OpClone):
        return (
            bytes([NODE_OP_CLONE])
            + _encode_varint(op.dest)
            + _encode_varint(op.length)
            + _emit_reference(op.reference)
            + _encode_varint(op.source_offset)
        )
    if isinstance(op, OpHole):
        return (
            bytes([NODE_OP_HOLE])
            + _encode_varint(op.dest)
            + _encode_varint(op.length)
        )
    if isinstance(op, OpZero):
        return (
            bytes([NODE_OP_ZERO])
            + _encode_varint(op.dest)
            + _encode_varint(op.length)
        )
    raise Pack4Error(f"not a node operation: {op!r}")


def emit_container(container: Container) -> bytes:
    out = bytearray(MAGIC)
    out += struct.pack(
        "<III", len(container.atoms), len(container.namespaces), len(container.nodes)
    )
    for atom in container.atoms:
        _check_atom(atom)
        out += atom.id
        out += _encode_varint(len(atom.data))
        out += atom.data
    for namespace in container.namespaces:
        _need_len(namespace.id, 16, "namespace id")
        _need_len(namespace.base, 16, "namespace base")
        out += namespace.id + namespace.base
        out += _encode_varint(len(namespace.ops))
        for op in namespace.ops:
            out += _emit_namespace_op(op)
    for node in container.nodes:
        _need_len(node.id, 16, "node id")
        out += node.id
        out += _encode_varint(node.logical_size)
        out += _emit_reference(node.base)
        out += _encode_varint(len(node.ops))
        for op in node.ops:
            out += _emit_node_op(op)
    return bytes(out)


def emit_view(view: View, *, endian: str = "<") -> bytes:
    format_char = _pick_endian(endian)
    _need_len(view.namespace_id, 16, "view namespace")
    _need_len(view.handle, 6, "view handle")
    if not (0 <= view.offset <= MAX_U64):
        raise Pack4Error("view offset does not fit in u64")
    if not (0 <= view.length <= MAX_U64):
        raise Pack4Error("view length does not fit in u64")
    return (
        VIEW_MAGIC
        + view.namespace_id
        + view.handle
        + struct.pack(format_char + "QQ", view.offset, view.length)
    )


def build_container(
    atoms: Sequence[Atom],
    namespaces: Sequence[Namespace],
    nodes: Sequence[Node],
) -> bytes:
    return emit_container(Container(list(atoms), list(namespaces), list(nodes)))


def build_view(
    namespace_id: bytes, handle: bytes, offset: int, length: int, *, endian: str = "<"
) -> bytes:
    return emit_view(View(namespace_id, handle, offset, length), endian=endian)


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------


class Resolver:
    """Range based pack/4 resolver.

    The resolver is reusable across many views of one container; namespace
    binding maps and node range results are cached.
    """

    def __init__(self, container: Container, *, max_evaluations: int = 1_000_000):
        self.container = container
        self.max_evaluations = max_evaluations
        self._bindings: Dict[bytes, Dict[bytes, bytes]] = {}
        self._memo: Dict[Tuple[bytes, int, int], Tuple[Segment, ...]] = {}
        self._coverage_cache: Dict[bytes, tuple] = {}
        self._active: set = set()
        self._evaluations = 0

    # -- namespace bindings -------------------------------------------------

    def bindings(self, namespace_id: bytes) -> Dict[bytes, bytes]:
        """Return the immutable final binding map of a namespace."""
        namespace_id = _as_bytes(namespace_id, "namespace id")
        _need_len(namespace_id, 16, "namespace id")
        cached = self._bindings.get(namespace_id)
        if cached is not None:
            return cached
        if namespace_id == ZERO_NAMESPACE:
            # The all-zero namespace is defined to be empty, regardless of
            # any record that might carry that id.
            self._bindings[namespace_id] = {}
            return self._bindings[namespace_id]

        chain: List[bytes] = []
        seen = set()
        current = namespace_id
        base_map: Dict[bytes, bytes] = {}

        while True:
            cached = self._bindings.get(current)
            if cached is not None:
                base_map = cached
                break
            if current == ZERO_NAMESPACE:
                self._bindings[current] = {}
                base_map = {}
                break
            if current in seen:
                raise Pack4Error(
                    f"namespace inheritance cycle at {current.hex()}"
                )
            seen.add(current)
            namespace = self.container.namespace_map.get(current)
            if namespace is None:
                # Unknown namespace behaves like an empty namespace.  This
                # also covers the all-zero namespace id.
                self._bindings[current] = {}
                base_map = {}
                break
            chain.append(current)
            if namespace.base == ZERO_NAMESPACE:
                base_map = {}
                break
            current = namespace.base

        mapping = base_map
        for ns_id in reversed(chain):
            namespace = self.container.namespace_map[ns_id]
            if namespace.ops:
                mapping = dict(mapping)  # snapshot: never mutate an older namespace
                self._apply_namespace_ops(mapping, namespace.ops)
            # Namespaces without operations share the parent's immutable map.
            self._bindings[ns_id] = mapping

        result = self._bindings.get(namespace_id)
        if result is None:
            # namespace_id was the unknown namespace handled above, or the
            # chain never stored it (cannot happen for known namespaces).
            result = mapping
            self._bindings[namespace_id] = result
        return result

    @staticmethod
    def _apply_namespace_ops(mapping: Dict[bytes, bytes], ops: Iterable[object]) -> None:
        for op in ops:
            if isinstance(op, OpBind):
                mapping[op.handle] = op.node_id
            elif isinstance(op, OpRemove):
                mapping.pop(op.handle, None)
            elif isinstance(op, OpExchange):
                first = mapping.pop(op.first, None)
                second = mapping.pop(op.second, None)
                if second is not None:
                    mapping[op.first] = second
                if first is not None:
                    mapping[op.second] = first
            else:
                raise Pack4Error(f"not a namespace operation: {op!r}")

    # -- reference lookup ---------------------------------------------------

    def lookup(self, reference: Reference) -> Optional[bytes]:
        """Resolve reference to a node id, or None when the handle is unbound."""
        return self.bindings(reference.namespace_id).get(reference.handle)

    def lookup_view(self, view: View) -> Optional[bytes]:
        return self.bindings(view.namespace_id).get(view.handle)

    # -- node ranges --------------------------------------------------------

    def resolve_node_range(
        self, node_id: bytes, offset: int, length: int
    ) -> Tuple[Segment, ...]:
        if length == 0:
            return ()
        if offset < 0 or length < 0:
            raise ResolutionError("negative node coordinate")

        key = (bytes(node_id), int(offset), int(length))
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        if key in self._active:
            node_hex = key[0].hex()
            raise CycleError(
                "coordinate depends on itself while resolving "
                f"node {node_hex} offset {offset} length {length}"
            )

        self._evaluations += 1
        if self._evaluations > self.max_evaluations:
            raise ResolutionError(
                f"evaluation budget exceeded ({self.max_evaluations}); "
                "the container may contain unbounded recursion"
            )

        self._active.add(key)
        try:
            segments = self._compute_node_range(node_id, offset, length)
        finally:
            self._active.discard(key)

        self._memo[key] = segments
        return segments

    def _compute_node_range(
        self, node_id: bytes, offset: int, length: int
    ) -> Tuple[Segment, ...]:
        node = self.container.node_map.get(node_id)
        if node is None:
            raise ResolutionError(f"reference to missing node {bytes(node_id).hex()}")

        if offset < 0:
            raise ResolutionError("negative node coordinate")

        size = node.logical_size
        request_end = offset + length

        segments: List[Segment] = []

        # If the whole request starts past the end of the node, every
        # coordinate is outside the logical size: one hole, no base lookup.
        if offset >= size:
            return (Segment(0, length, False, None),)

        inside_start = offset
        inside_end = min(request_end, size)

        if inside_end > inside_start:
            coverage = self._coverage(node, inside_start, inside_end)
            cursor = inside_start
            for start, end, op in coverage:
                if start > cursor:
                    segments.extend(
                        self._inherit_gap(node.base, cursor, start, offset)
                    )
                segments.extend(self._resolve_op(op, start, end, offset))
                cursor = end
            if cursor < inside_end:
                segments.extend(
                    self._inherit_gap(node.base, cursor, inside_end, offset)
                )

        if request_end > inside_end:
            segments.append(
                Segment(
                    inside_end - offset,
                    request_end - inside_end,
                    False,
                    None,
                )
            )

        return tuple(segments)

    def _node_coverage(self, node: Node):
        """Return (intervals, starts) for the node's final operator coverage.

        Painting only looks at operator metadata (destinations, lengths,
        identities); it never dereferences a base or clone reference, so
        caching the full-node coverage does not make any unrequested
        coordinate live.
        """
        cached = self._coverage_cache.get(node.id)
        if cached is not None:
            return cached

        size = node.logical_size
        intervals: List[Tuple[int, int, object]] = []
        if size > 0:
            # Fast path: ascending, disjoint destinations need no painting.
            simple = True
            previous_end = -1
            selected: List[Tuple[int, int, object]] = []
            for op in node.ops:
                op_length = op.length
                if op_length <= 0:
                    continue
                if op.dest < previous_end:
                    simple = False
                    break
                previous_end = op.dest + op_length
                clipped_start = max(op.dest, 0)
                clipped_end = min(op.dest + op_length, size)
                if clipped_start < clipped_end:
                    selected.append((clipped_start, clipped_end, op))
            if simple:
                intervals = selected
            else:
                painted: List[List[object]] = []
                for op in node.ops:
                    op_length = op.length
                    if op_length <= 0:
                        continue
                    clipped_start = max(op.dest, 0)
                    clipped_end = min(op.dest + op_length, size)
                    if clipped_start < clipped_end:
                        self._paint(painted, clipped_start, clipped_end, op)
                painted.sort(key=lambda item: item[0])
                intervals = [
                    (start, end, op) for start, end, op in painted
                ]

        starts = tuple(interval[0] for interval in intervals)
        result = (tuple(intervals), starts)
        self._coverage_cache[node.id] = result
        return result

    def _coverage(self, node: Node, start: int, end: int):
        """Select the final node operators intersecting [start, end)."""
        intervals, starts = self._node_coverage(node)
        if not intervals:
            return []

        index = bisect.bisect_right(starts, start) - 1
        if index < 0:
            index = 0
        selected: List[List[object]] = []
        for interval_start, interval_end, op in intervals[index:]:
            if interval_start >= end:
                break
            if interval_end <= start:
                continue
            clipped_start = max(interval_start, start)
            clipped_end = min(interval_end, end)
            if clipped_start < clipped_end:
                selected.append([clipped_start, clipped_end, op])
        return selected

    @staticmethod
    def _paint(
        intervals: List[List[object]], start: int, end: int, piece: object
    ) -> None:
        kept: List[List[object]] = []
        for old_start, old_end, old_piece in intervals:
            if old_end <= start or old_start >= end:
                kept.append([old_start, old_end, old_piece])
            else:
                if old_start < start:
                    kept.append([old_start, start, old_piece])
                if old_end > end:
                    kept.append([end, old_end, old_piece])
        kept.append([start, end, piece])
        kept.sort(key=lambda item: item[0])
        intervals[:] = kept

    def _inherit_gap(
        self, reference: Reference, start: int, end: int, request_offset: int
    ) -> List[Segment]:
        length = end - start
        target = self.lookup(reference)
        relative = start - request_offset
        if target is None:
            return [Segment(relative, length, False, None)]
        children = self.resolve_node_range(target, start, length)
        return [
            Segment(
                relative + child.start, child.length, child.allocated, child.data
            )
            for child in children
        ]

    def _resolve_op(self, op: object, start: int, end: int, request_offset: int) -> List[Segment]:
        length = end - start
        relative = start - request_offset

        if isinstance(op, OpHole):
            return [Segment(relative, length, False, None)]

        if isinstance(op, OpZero):
            return [Segment(relative, length, True, None)]

        if isinstance(op, OpLiteral):
            atom = self.container.atom_map.get(op.atom_id)
            if atom is None:
                raise ResolutionError(
                    f"literal references missing atom {bytes(op.atom_id).hex()}"
                )
            source_start = op.source_offset + (start - op.dest)
            available = 0
            if source_start < len(atom.data):
                available = min(length, len(atom.data) - source_start)
            result: List[Segment] = []
            if available > 0:
                result.append(
                    Segment(
                        relative,
                        available,
                        True,
                        bytes(atom.data[source_start:source_start + available]),
                    )
                )
            if available < length:
                # The atom has no bytes for this range; treat it as a hole
                # rather than inventing allocated zeroes.
                result.append(
                    Segment(relative + available, length - available, False, None)
                )
            return result

        if isinstance(op, OpClone):
            target = self.lookup(op.reference)
            if target is None:
                return [Segment(relative, length, False, None)]
            source_start = op.source_offset + (start - op.dest)
            children = self.resolve_node_range(target, source_start, length)
            return [
                Segment(
                    relative + child.start,
                    child.length,
                    child.allocated,
                    child.data,
                )
                for child in children
            ]

        raise ResolutionError(f"not a node operation: {op!r}")

    # -- views and export ---------------------------------------------------

    def resolve_view_segments(self, view: View) -> Tuple[Segment, ...]:
        try:
            if view.length == 0:
                return ()
            target = self.lookup_view(view)
            if target is None:
                return (Segment(0, view.length, False, None),)
            return self.resolve_node_range(target, view.offset, view.length)
        except RecursionError:
            raise ResolutionError(
                "resolution exceeded the Python recursion limit; the container "
                "contains a deep or cyclic reference chain"
            ) from None

    def canonical_export(self, view: View) -> bytes:
        segments = self.resolve_view_segments(view)
        return b"".join(iter_export(view.length, segments))

    def write_canonical_export(self, view: View, fileobj) -> None:
        segments = self.resolve_view_segments(view)
        write_export(fileobj, view.length, segments)


# ---------------------------------------------------------------------------
# canonical export
# ---------------------------------------------------------------------------


def group_runs(
    segments: Sequence[Segment], requested_length: int
) -> Tuple[Run, ...]:
    """Validate coverage and collapse segments into maximal allocation runs."""
    if requested_length < 0:
        raise ResolutionError("negative requested length")
    runs: List[Run] = []
    current_allocated: Optional[bool] = None
    current_start = 0
    current_length = 0
    current_segments: List[Segment] = []
    position = 0

    for segment in segments:
        if segment.length == 0:
            continue
        if segment.start != position:
            raise ResolutionError(
                "internal coverage error: segment starts at "
                f"{segment.start}, expected {position}"
            )
        if segment.length < 0:
            raise ResolutionError("negative segment length")
        if segment.allocated:
            if segment.data is not None and len(segment.data) != segment.length:
                raise ResolutionError(
                    "allocated segment data length mismatch: "
                    f"{len(segment.data)} != {segment.length}"
                )
        elif segment.data is not None:
            raise ResolutionError("hole segment carries data")

        if current_allocated is None:
            current_allocated = segment.allocated
            current_start = segment.start
            current_length = segment.length
            current_segments = [segment]
        elif current_allocated == segment.allocated:
            current_length += segment.length
            current_segments.append(segment)
        else:
            runs.append(
                Run(current_allocated, current_start, current_length, tuple(current_segments))
            )
            current_allocated = segment.allocated
            current_start = segment.start
            current_length = segment.length
            current_segments = [segment]
        position += segment.length

    if current_allocated is not None:
        runs.append(
            Run(current_allocated, current_start, current_length, tuple(current_segments))
        )

    if position != requested_length:
        raise ResolutionError(
            f"resolved {position} bytes but the view requests {requested_length}"
        )

    return tuple(runs)


def iter_export(
    requested_length: int, segments: Sequence[Segment]
) -> Iterator[bytes]:
    """Yield the canonical R4SP export as a sequence of byte chunks.

    Hole payloads are never materialized; allocated zero runs are streamed in
    bounded chunks.
    """
    runs = group_runs(segments, requested_length)
    yield EXPORT_MAGIC + struct.pack(">Q", requested_length)
    for run in runs:
        yield struct.pack(
            ">BQQ", 1 if run.allocated else 0, run.start, run.length
        )
        if run.allocated:
            for segment in run.segments:
                if segment.data is not None:
                    yield segment.data
                else:
                    remaining = segment.length
                    while remaining:
                        step = min(remaining, len(_ZERO_BLOCK))
                        yield _ZERO_BLOCK[:step]
                        remaining -= step


def write_export(fileobj, requested_length: int, segments: Sequence[Segment]) -> None:
    for chunk in iter_export(requested_length, segments):
        fileobj.write(chunk)


# ---------------------------------------------------------------------------
# public convenience wrapper
# ---------------------------------------------------------------------------


def resolve_view(
    container_bytes: bytes,
    view_bytes: bytes,
    *,
    view_endian: str = "<",
    max_evaluations: int = 1_000_000,
) -> bytes:
    """Resolve a view and return the canonical R4SP export bytes.

    This is the entry point the challenge pipeline imports:

        from pack4 import resolve_view
        canonical = resolve_view(container_bytes, view_bytes)

    ``view_endian`` normally stays at the documented little-endian default;
    pass ">" only to test the alternative reading of the view's two u64 fields.
    """
    container = parse_container(container_bytes)
    view = parse_view(view_bytes, endian=view_endian)
    return Resolver(container, max_evaluations=max_evaluations).canonical_export(view)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _summary_lines(container: Container, view: View, resolver: Resolver,
                   segments: Sequence[Segment], runs: Sequence[Run]) -> List[str]:
    lines = [
        f"container: magic=RRPCK4 atoms={len(container.atoms)} "
        f"namespaces={len(container.namespaces)} nodes={len(container.nodes)}"
    ]
    inode, incarnation = handle_parts(view.handle)
    lines.append(
        f"view: namespace={view.namespace_id.hex()} "
        f"handle=0x{view.handle.hex()} (inode={inode} incarnation={incarnation}) "
        f"offset={view.offset} length={view.length}"
    )
    target = resolver.lookup_view(view)
    if target is None:
        lines.append("bound node: <unbound handle -> all holes>")
    else:
        node = container.node_map.get(target)
        if node is None:
            lines.append(f"bound node: {target.hex()} (missing from node table)")
        else:
            lines.append(
                f"bound node: {target.hex()} logical_size={node.logical_size} "
                f"ops={len(node.ops)}"
            )
    allocated_bytes = sum(run.length for run in runs if run.allocated)
    hole_bytes = sum(run.length for run in runs if not run.allocated)
    lines.append(
        f"runs: {len(runs)} allocated={allocated_bytes} holes={hole_bytes}"
    )
    for index, run in enumerate(runs[:12]):
        kind = "alloc" if run.allocated else "hole "
        extra = ""
        if run.allocated:
            preview = bytearray()
            for segment in run.segments:
                if len(preview) >= 16:
                    break
                take = min(segment.length, 16 - len(preview))
                if segment.data is None:
                    preview += bytes(take)
                else:
                    preview += segment.data[:take]
            extra = f" data[:16]={bytes(preview).hex()}"
        lines.append(
            f"  [{index}] {kind} start={run.start} length={run.length}{extra}"
        )
    if len(runs) > 12:
        lines.append(f"  ... {len(runs) - 12} more run(s)")
    return lines


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="pack4.py",
        description="Resolve an RRPCK4 pack/4 view to a canonical R4SP export.",
    )
    parser.add_argument("container", help="pack/4 container file (RRPCK4...)")
    parser.add_argument("view", help="view file (R4VW...)")
    parser.add_argument("--out", help="write export here instead of stdout")
    parser.add_argument(
        "--view-endian",
        choices=("le", "be"),
        default="le",
        help="byte order of the view's offset/length fields (default: le)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="suppress the stderr summary"
    )
    args = parser.parse_args(argv)

    try:
        with open(args.container, "rb") as handle:
            container_bytes = handle.read()
        with open(args.view, "rb") as handle:
            view_bytes = handle.read()

        container = parse_container(container_bytes)
        view = parse_view(view_bytes, endian=args.view_endian)
        resolver = Resolver(container)
        segments = resolver.resolve_view_segments(view)
        runs = group_runs(segments, view.length)

        if not args.quiet:
            for line in _summary_lines(container, view, resolver, segments, runs):
                print(line, file=sys.stderr)

        if args.out:
            with open(args.out, "wb") as handle:
                for chunk in iter_export(view.length, segments):
                    handle.write(chunk)
        else:
            output = sys.stdout.buffer
            for chunk in iter_export(view.length, segments):
                output.write(chunk)
            output.flush()
    except (Pack4Error, OSError) as exc:
        print(f"pack4: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
