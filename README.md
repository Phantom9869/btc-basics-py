# btc-basics-py

Small Python implementations of the hashing and encoding pieces behind
Bitcoin addresses: SHA-256d, HASH160, Base58Check, Wallet Import Format
and P2PKH/P2SH address construction. Written while going through
Mastering Bitcoin. Standard library only.

## Install

```
pip install -e .
```

That also installs a `btcbasics` command. `python -m btcbasics` works
without installing.

## Usage

```
python -m btcbasics hash sha256d 0x68656c6c6f
python -m btcbasics address p2pkh 62e907b15cbf27d5425399ebf6f0fb50ebb88f18
python -m btcbasics decode 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
python -m btcbasics wif encode 0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d --uncompressed
python -m btcbasics encode 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 --version 0x00
```

Hex arguments accept a `0x` prefix and surrounding whitespace. `decode`
skips leading and trailing whitespace on the address or WIF string,
recognizes P2PKH, P2SH and WIF version bytes, and checks the checksum.

`address p2pkh` takes a 20-byte HASH160 or a 33/65-byte public key.
`address p2sh` takes a 20-byte script hash. Both accept `--testnet`.

The same helpers are available as a library:

```
from btcbasics import p2pkh_address, encode_wif, sha256d
```

## Tests

```
pip install pytest
pytest
```

The tests use published vectors, including the genesis block hash, the
address it paid to, and a well-known WIF key.
