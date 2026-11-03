# btc-basics-py

Small Python implementations of the hashing and encoding pieces behind
Bitcoin addresses: SHA-256d, HASH160 and Base58Check. Written while going
through Mastering Bitcoin. Standard library only.

## Usage

```
python -m btcbasics hash sha256d 68656c6c6f
python -m btcbasics encode 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 --version 0x00
python -m btcbasics decode 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

`encode` takes a hex payload and an optional version byte. `decode` checks
the checksum and prints the version byte and payload.

## Tests

```
pip install pytest
pytest
```

The tests use published vectors, including the genesis block hash and the
address it paid to.
