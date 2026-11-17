"""Parse and serialize raw Bitcoin transactions, including SegWit."""

from typing import List, NamedTuple, Optional, Tuple

from .hashes import BytesLike, _as_bytes, sha256d
from .txid import hash_from_txid, txid_from_hash
from .varint import decode_compact_size, encode_compact_size

COINBASE_PREV = "00" * 32
COINBASE_INDEX = 0xFFFFFFFF


def _read_u32(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 4:
        raise ValueError("truncated transaction")
    return int.from_bytes(data[:4], "little"), data[4:]


def _read_u64(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 8:
        raise ValueError("truncated transaction")
    return int.from_bytes(data[:8], "little"), data[8:]


def _read_bytes(data: bytes) -> Tuple[bytes, bytes]:
    length, rest = decode_compact_size(data)
    if len(rest) < length:
        raise ValueError("truncated transaction")
    return rest[:length], rest[length:]


class TxIn(NamedTuple):
    prev_txid: str
    prev_index: int
    script_sig: bytes
    sequence: int
    witness: Tuple[bytes, ...] = ()


class TxOut(NamedTuple):
    value: int
    script_pubkey: bytes


class Transaction(NamedTuple):
    version: int
    inputs: Tuple[TxIn, ...]
    outputs: Tuple[TxOut, ...]
    locktime: int
    segwit: bool

    @property
    def is_coinbase(self) -> bool:
        return (
            len(self.inputs) == 1
            and self.inputs[0].prev_txid == COINBASE_PREV
            and self.inputs[0].prev_index == COINBASE_INDEX
        )

    def serialize(self, *, witness: Optional[bool] = None) -> bytes:
        """Serialize the transaction.

        When witness is True (the default for a SegWit transaction), the
        marker, flag and witness stacks are included. txid hashes the
        non-witness serialization; wtxid hashes the full one.
        """
        include_witness = self.segwit if witness is None else witness
        if include_witness and not self.segwit:
            include_witness = False
        parts: List[bytes] = [self.version.to_bytes(4, "little", signed=True)]
        if include_witness:
            parts.append(b"\x00\x01")
        parts.append(encode_compact_size(len(self.inputs)))
        for vin in self.inputs:
            parts.append(hash_from_txid(vin.prev_txid))
            if not 0 <= vin.prev_index <= 0xFFFFFFFF:
                raise ValueError("previous output index must fit in 4 bytes")
            if not 0 <= vin.sequence <= 0xFFFFFFFF:
                raise ValueError("sequence must fit in 4 bytes")
            parts.append(vin.prev_index.to_bytes(4, "little"))
            script = bytes(vin.script_sig)
            parts.append(encode_compact_size(len(script)))
            parts.append(script)
            parts.append(vin.sequence.to_bytes(4, "little"))
        parts.append(encode_compact_size(len(self.outputs)))
        for vout in self.outputs:
            if isinstance(vout.value, bool) or not isinstance(vout.value, int):
                raise TypeError("output value must be an int")
            if not 0 <= vout.value <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError("output value must fit in 8 bytes")
            script = bytes(vout.script_pubkey)
            parts.append(vout.value.to_bytes(8, "little"))
            parts.append(encode_compact_size(len(script)))
            parts.append(script)
        if include_witness:
            for vin in self.inputs:
                parts.append(encode_compact_size(len(vin.witness)))
                for item in vin.witness:
                    item_b = bytes(item)
                    parts.append(encode_compact_size(len(item_b)))
                    parts.append(item_b)
        if not 0 <= self.locktime <= 0xFFFFFFFF:
            raise ValueError("locktime must fit in 4 bytes")
        parts.append(self.locktime.to_bytes(4, "little"))
        return b"".join(parts)

    def txid(self) -> str:
        return txid_from_hash(sha256d(self.serialize(witness=False)))

    def wtxid(self) -> str:
        return txid_from_hash(sha256d(self.serialize(witness=True)))

    def size(self) -> int:
        return len(self.serialize(witness=True))

    def base_size(self) -> int:
        return len(self.serialize(witness=False))

    def weight(self) -> int:
        # BIP 141: base bytes weigh 4, witness bytes (incl. marker/flag) weigh 1.
        return 3 * self.base_size() + self.size()

    def vsize(self) -> int:
        return (self.weight() + 3) // 4


def parse_transaction(data: BytesLike) -> Transaction:
    """Parse a raw Bitcoin transaction, with or without a witness."""
    rest = _as_bytes(data, "parse_transaction")
    if len(rest) < 10:
        raise ValueError("truncated transaction")
    version, rest = _read_u32(rest)
    # Version is a signed int32 on the wire; re-interpret.
    if version >= 0x80000000:
        version -= 0x100000000

    segwit = False
    if rest and rest[0] == 0x00:
        if len(rest) < 2:
            raise ValueError("truncated transaction")
        flag = rest[1]
        if flag == 0:
            raise ValueError("transaction has no inputs")
        if flag != 1:
            raise ValueError("unsupported SegWit flag")
        segwit = True
        rest = rest[2:]

    n_in, rest = decode_compact_size(rest)
    if n_in == 0:
        raise ValueError("transaction has no inputs")
    inputs: List[TxIn] = []
    for _ in range(n_in):
        if len(rest) < 36:
            raise ValueError("truncated transaction")
        prev_hash, rest = rest[:32], rest[32:]
        prev_index, rest = _read_u32(rest)
        script, rest = _read_bytes(rest)
        sequence, rest = _read_u32(rest)
        inputs.append(
            TxIn(
                prev_txid=txid_from_hash(prev_hash),
                prev_index=prev_index,
                script_sig=script,
                sequence=sequence,
            )
        )

    n_out, rest = decode_compact_size(rest)
    outputs: List[TxOut] = []
    for _ in range(n_out):
        value, rest = _read_u64(rest)
        script, rest = _read_bytes(rest)
        outputs.append(TxOut(value=value, script_pubkey=script))

    if segwit:
        filled: List[TxIn] = []
        for vin in inputs:
            n_items, rest = decode_compact_size(rest)
            items = []
            for _ in range(n_items):
                item, rest = _read_bytes(rest)
                items.append(item)
            filled.append(vin._replace(witness=tuple(items)))
        inputs = filled

    locktime, rest = _read_u32(rest)
    if rest:
        raise ValueError("trailing data after transaction")
    return Transaction(
        version=version,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        locktime=locktime,
        segwit=segwit,
    )
