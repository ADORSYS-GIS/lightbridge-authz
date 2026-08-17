"""Minimal, dependency-free CBOR (RFC 8949) codec for the IT test runners.

ADR-0013 ("CBOR is the only transport codec") removed the JSON secondary codec from
`authz-api`'s and `authz-budget`'s RPC routers (`crates/lightbridge-authz-rest/src/lib.rs`), so
`authorino_it.py`/`servers_it.py` -- both plain `python:3.12-slim` containers with no package
install step (see `compose.it.yaml`) -- need to speak CBOR to `POST /rpc/{op_id}` themselves.
Rather than adding a `pip install` step to a self-hosted CI runner (network dependency, version
drift -- see this repo's own house rules on unpinned dependencies in a release/CI pipeline), this
hand-rolls exactly the subset of CBOR these two scripts' request/response shapes need: maps with
text-string keys, arrays, text strings, booleans, null, and integers. Definite-length encoding only
on the way out (what every real CBOR encoder, including the Rust server's `minicbor`, produces);
decoding accepts both definite- and indefinite-length items defensively, plus IEEE-754 floats, in
case a response ever carries one.

Not a general-purpose CBOR library: no tags, no byte-string decoding beyond raw passthrough, no
bignums. If the server ever sends a shape outside that subset, `decode` raises `ValueError` loudly
rather than silently misinterpreting it.
"""

import struct

_MAJOR_UINT = 0
_MAJOR_NEGINT = 1
_MAJOR_BYTES = 2
_MAJOR_TEXT = 3
_MAJOR_ARRAY = 4
_MAJOR_MAP = 5
_MAJOR_TAG = 6
_MAJOR_SIMPLE = 7

_BREAK = 0xFF


def encode(value) -> bytes:
    out = bytearray()
    _encode_into(out, value)
    return bytes(out)


def _encode_head(out: bytearray, major: int, length: int) -> None:
    prefix = major << 5
    if length < 24:
        out.append(prefix | length)
    elif length < 2**8:
        out.append(prefix | 24)
        out.append(length)
    elif length < 2**16:
        out.append(prefix | 25)
        out.extend(struct.pack(">H", length))
    elif length < 2**32:
        out.append(prefix | 26)
        out.extend(struct.pack(">I", length))
    else:
        out.append(prefix | 27)
        out.extend(struct.pack(">Q", length))


def _encode_into(out: bytearray, value) -> None:
    if value is None:
        out.append(0xF6)
    elif value is True:
        out.append(0xF5)
    elif value is False:
        out.append(0xF4)
    elif isinstance(value, int):
        if value >= 0:
            _encode_head(out, _MAJOR_UINT, value)
        else:
            _encode_head(out, _MAJOR_NEGINT, -1 - value)
    elif isinstance(value, str):
        encoded = value.encode("utf-8")
        _encode_head(out, _MAJOR_TEXT, len(encoded))
        out.extend(encoded)
    elif isinstance(value, (bytes, bytearray)):
        _encode_head(out, _MAJOR_BYTES, len(value))
        out.extend(value)
    elif isinstance(value, (list, tuple)):
        _encode_head(out, _MAJOR_ARRAY, len(value))
        for item in value:
            _encode_into(out, item)
    elif isinstance(value, dict):
        _encode_head(out, _MAJOR_MAP, len(value))
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"cbor_min only encodes string map keys, got {key!r}")
            _encode_into(out, key)
            _encode_into(out, item)
    else:
        raise ValueError(f"cbor_min cannot encode value of type {type(value)!r}: {value!r}")


class _Cursor:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        chunk = self.data[self.pos : self.pos + n]
        if len(chunk) != n:
            raise ValueError("cbor_min: unexpected end of input")
        self.pos += n
        return chunk

    def read_byte(self) -> int:
        return self.read(1)[0]


def decode(data: bytes):
    cursor = _Cursor(data)
    value = _decode_value(cursor)
    return value


def _read_length(cursor: _Cursor, additional: int) -> "int | None":
    """Returns the length, or None for an indefinite-length item (additional == 31)."""
    if additional < 24:
        return additional
    if additional == 24:
        return cursor.read_byte()
    if additional == 25:
        return struct.unpack(">H", cursor.read(2))[0]
    if additional == 26:
        return struct.unpack(">I", cursor.read(4))[0]
    if additional == 27:
        return struct.unpack(">Q", cursor.read(8))[0]
    if additional == 31:
        return None
    raise ValueError(f"cbor_min: reserved additional-info value {additional}")


def _decode_value(cursor: _Cursor):
    head = cursor.read_byte()
    major = head >> 5
    additional = head & 0x1F

    if major == _MAJOR_UINT:
        return _read_length(cursor, additional)
    if major == _MAJOR_NEGINT:
        return -1 - _read_length(cursor, additional)
    if major == _MAJOR_BYTES:
        return _read_string_like(cursor, additional, text=False)
    if major == _MAJOR_TEXT:
        return _read_string_like(cursor, additional, text=True)
    if major == _MAJOR_ARRAY:
        length = _read_length(cursor, additional)
        items = []
        if length is None:
            while cursor.data[cursor.pos] != _BREAK:
                items.append(_decode_value(cursor))
            cursor.read_byte()
        else:
            for _ in range(length):
                items.append(_decode_value(cursor))
        return items
    if major == _MAJOR_MAP:
        length = _read_length(cursor, additional)
        result = {}
        if length is None:
            while cursor.data[cursor.pos] != _BREAK:
                key = _decode_value(cursor)
                result[key] = _decode_value(cursor)
            cursor.read_byte()
        else:
            for _ in range(length):
                key = _decode_value(cursor)
                result[key] = _decode_value(cursor)
        return result
    if major == _MAJOR_TAG:
        _read_length(cursor, additional)
        return _decode_value(cursor)
    if major == _MAJOR_SIMPLE:
        return _decode_simple(cursor, additional)
    raise ValueError(f"cbor_min: unsupported major type {major}")


def _read_string_like(cursor: _Cursor, additional: int, text: bool):
    length = _read_length(cursor, additional)
    if length is None:
        chunks = []
        while cursor.data[cursor.pos] != _BREAK:
            chunk_head = cursor.read_byte()
            chunk_major = chunk_head >> 5
            chunk_additional = chunk_head & 0x1F
            expected_major = _MAJOR_TEXT if text else _MAJOR_BYTES
            if chunk_major != expected_major:
                raise ValueError("cbor_min: indefinite-length chunk type mismatch")
            chunk_len = _read_length(cursor, chunk_additional)
            chunks.append(cursor.read(chunk_len))
        cursor.read_byte()
        raw = b"".join(chunks)
    else:
        raw = cursor.read(length)
    return raw.decode("utf-8") if text else raw


def _decode_simple(cursor: _Cursor, additional: int):
    if additional == 20:
        return False
    if additional == 21:
        return True
    if additional == 22:
        return None
    if additional == 23:
        return None
    if additional == 24:
        cursor.read_byte()
        return None
    if additional == 25:
        return struct.unpack(">e", cursor.read(2))[0]
    if additional == 26:
        return struct.unpack(">f", cursor.read(4))[0]
    if additional == 27:
        return struct.unpack(">d", cursor.read(8))[0]
    raise ValueError(f"cbor_min: unsupported simple value additional-info {additional}")
