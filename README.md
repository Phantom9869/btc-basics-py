# btc-basics-py

Small Python implementations of the hashing and encoding pieces behind
Bitcoin addresses: SHA-256d, HASH160, Base58Check, Bech32, Bech32m, Wallet
Import Format, CompactSize varints, signed-message hashing, txid byte
order, BIP 39 mnemonic-to-seed, BIP 32 extended keys, block headers, raw transactions, satoshi amounts, and P2PKH/P2SH/P2WPKH/P2WSH/P2TR address
construction. Written while going through Mastering Bitcoin. Standard
library only.

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
python -m btcbasics address p2tr 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
python -m btcbasics decode 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
python -m btcbasics decode bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
python -m btcbasics decode bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0
python -m btcbasics wif encode 0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d --uncompressed
python -m btcbasics encode 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 --version 0x00
python -m btcbasics --json decode bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
python -m btcbasics validate bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0
python -m btcbasics scriptpubkey bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0
python -m btcbasics scriptpubkey --from-script 512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
python -m btcbasics varint encode 253
python -m btcbasics varint decode 0xfdfd00
python -m btcbasics message-hash "Hello World"
python -m btcbasics txid 3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a
python -m btcbasics seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR
python -m btcbasics xkey master 000102030405060708090a0b0c0d0e0f
python -m btcbasics xkey decode xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
python -m btcbasics header 0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c
python -m btcbasics tx 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000
python -m btcbasics amount 50
python -m btcbasics amount 5000000000 --from-sats
```

Hex arguments accept a `0x` prefix and surrounding whitespace. `decode`
skips leading and trailing whitespace on the address or WIF string,
recognizes P2PKH, P2SH, WIF, native SegWit v0 and Taproot (P2TR) addresses, and checks
the checksum.

`validate` classifies any of those (plus unknown Base58 version bytes) as a
type and network, and exits 0 only when the string is valid. It is meant for
scripts that need to ask "what is this?" without picking a decode path.

`scriptpubkey` prints the scriptPubKey for a payment address.
`--from-script` goes the other way; add `--testnet` to build a testnet
address, since a scriptPubKey does not itself record the network.

`varint` encodes and decodes Bitcoin's CompactSize integers, the
variable-length length prefix used in transactions and inventory messages.
Decode rejects truncated or non-canonical encodings, the same way Bitcoin
Core does.

`message-hash` returns the SHA256d digest Bitcoin Core signs for a text
message: the magic header `Bitcoin Signed Message:\n`, each part prefixed
with a CompactSize length. The same helper accepts `bytes` in the library.

`txid` reverses a 32-byte hex value between the internal byte order used
in block headers and the display order used for txids and block hashes.
The example above is the genesis coinbase merkle root, and prints that
transaction's txid.

`seed` derives a 64-byte BIP 39 seed from an English mnemonic, with an
optional passphrase. The mnemonic is checked against the official English
wordlist (bundled, and verified by its published SHA-256) and its checksum
before PBKDF2-HMAC-SHA512 is applied.

`xkey decode` parses a BIP 32 `xprv`/`xpub`/`tprv`/`tpub` string into its
depth, parent fingerprint, child number, chain code and key. `xkey master`
derives the master private key from a seed with HMAC-SHA512, the same way
BIP 32 specifies. Child-key derivation is not included, because it needs
elliptic-curve point arithmetic; the official serialization vectors and
BIP 39 `xprv` strings are enough to check the format itself.

`header` parses an 80-byte block header, prints its fields, and checks the
proof of work: SHA256d of the header (in display byte order) must be less
than or equal to the target decoded from compact nBits. The genesis header
and block 170 are used as test vectors. Difficulty is the genesis target
divided by the header's target, so genesis has difficulty 1.

`tx` parses a raw transaction, including SegWit marker, flag and witness
data. It prints the version, input and output counts, locktime, txid,
wtxid, size, weight and vsize. The tests use the genesis coinbase and the
first confirmed SegWit transaction (block 481,824).

`amount` converts between BTC and satoshis. There are 100,000,000
satoshis in one BTC, and amounts must be in the range 0 through
21,000,000 BTC with at most eight decimal places. `--from-sats` goes
the other way.

`address p2pkh` takes a 20-byte HASH160 or a 33/65-byte public key.
`address p2sh` takes a 20-byte script hash. `address p2wpkh` takes a
20-byte HASH160 or a 33-byte compressed public key. `address p2wsh`
takes a 32-byte SHA-256 script hash. `address p2tr` takes a 32-byte
x-only public key. All of them accept `--testnet`.

`--json` prints a single JSON object instead of text, useful when calling
the CLI from a script. The flag can go before or after the subcommand.
Errors still go to stderr as text.

The same helpers are available as a library:

```
from btcbasics import address_to_scriptpubkey, btc_to_sats, encode_compact_size, identify_address, master_from_seed, mnemonic_to_seed, parse_block_header, parse_transaction, p2pkh_address, p2tr_address, p2wpkh_address, encode_wif, sha256d, signed_message_hash, txid_from_hash
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

The tests use published vectors, including the genesis block header and hash, the
address it paid to, the genesis coinbase transaction, the first SegWit transaction, a well-known WIF key,
Bitcoin Core's CompactSize
canonical and non-canonical cases, the official BIP 39 English mnemonic
and xprv vectors, the official BIP 32 extended-key strings, the official BIP 173 Bech32 / SegWit v0 addresses, and the
official BIP 350 Bech32m and SegWit v1+ addresses.
