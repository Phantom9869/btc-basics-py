"""Bitcoin merkle roots from transaction ids."""

from typing import Sequence

from .hashes import sha256d
from .txid import hash_from_txid, txid_from_hash


def merkle_root(txids: Sequence[str]) -> str:
    """Compute a merkle root from display-order transaction ids.

    Each txid is reversed to internal byte order, then paired and
    hashed with SHA256d. If a level has an odd number of hashes, the
    last hash is duplicated, matching Bitcoin's merkle tree. The root
    is returned in display byte order, the same way a block header
    shows it.

    A single transaction (the genesis block, for example) has a merkle
    root equal to its txid.
    """
    if not isinstance(txids, (list, tuple)):
        # Accept any sequence except a bare string, which would iterate
        # character by character.
        if isinstance(txids, str):
            raise TypeError("merkle_root() expected a sequence of txids, got str")
        try:
            txids = list(txids)
        except TypeError as exc:
            raise TypeError(
                f"merkle_root() expected a sequence of txids, got {type(txids).__name__}"
            ) from exc
    if not txids:
        raise ValueError("at least one transaction id is required")
    level = [hash_from_txid(txid) for txid in txids]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return txid_from_hash(level[0])
