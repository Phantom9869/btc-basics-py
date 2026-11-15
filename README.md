# btc-basics-py

Small Python implementations of the hashing and encoding pieces behind
Bitcoin addresses: SHA-256d, HASH160, Base58Check, Bech32, Bech32m, Wallet Import
Format and P2PKH/P2SH/P2WPKH/P2WSH address construction. Written while
going through Mastering Bitcoin. Standard library only.

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
python -m btcbasics address p2wpkh 751e76e8199196d454941c45d1b3a323f1433bd6
python -m btcbasics decode 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
python -m btcbasics decode bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
python -m btcbasics wif encode 0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d --uncompressed
python -m btcbasics encode 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 --version 0x00
python -m btcbasics --json decode bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

Hex arguments accept a `0x` prefix and surrounding whitespace. `decode`
skips leading and trailing whitespace on the address or WIF string,
recognizes P2PKH, P2SH, WIF and native SegWit v0 addresses, and checks
the checksum.

`address p2pkh` takes a 20-byte HASH160 or a 33/65-byte public key.
`address p2sh` takes a 20-byte script hash. `address p2wpkh` takes a
20-byte HASH160 or a 33-byte compressed public key. `address p2wsh`
takes a 32-byte SHA-256 script hash. All of them accept `--testnet`.

`--json` prints a single JSON object instead of text, useful when calling
the CLI from a script. The flag can go before or after the subcommand.
Errors still go to stderr as text.

The same helpers are available as a library:

```
from btcbasics import p2pkh_address, p2wpkh_address, encode_wif, sha256d
```

The package ships a `py.typed` marker so type checkers can use the
annotations on those helpers.

## Tests

```
pip install pytest
pytest
```

Pushes and pull requests also run that suite on Python 3.9, 3.11 and 3.13
via GitHub Actions.

The tests use published vectors, including the genesis block hash, the
address it paid to, a well-known WIF key, the official BIP 173 Bech32 /
SegWit v0 addresses, and the official BIP 350 Bech32m strings.
