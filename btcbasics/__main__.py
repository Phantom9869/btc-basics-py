import argparse
import sys

from .base58 import b58decode_check, b58encode_check
from .hashes import hash160, sha256, sha256d
from .wif import MAINNET_WIF, TESTNET_WIF, decode_wif, encode_wif

VERSIONS = {
    0x00: "mainnet P2PKH",
    0x05: "mainnet P2SH",
    0x6F: "testnet P2PKH",
    0xC4: "testnet P2SH",
}


def parse_hex(text):
    # Allow the 0x prefix already accepted by --version, and ignore
    # surrounding whitespace from pasted values.
    raw = text.strip()
    if raw[:2].lower() == "0x":
        raw = raw[2:]
    try:
        return bytes.fromhex(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not valid hex: {text}")


def cmd_hash(args):
    funcs = {"sha256": sha256, "sha256d": sha256d, "hash160": hash160}
    print(funcs[args.algo](args.data).hex())


def cmd_encode(args):
    payload = args.payload
    if args.version is not None:
        if not 0 <= args.version <= 0xFF:
            print("version must fit in one byte", file=sys.stderr)
            return 1
        payload = bytes([args.version]) + payload
    print(b58encode_check(payload))


def cmd_decode(args):
    try:
        payload = b58decode_check(args.address)
    except ValueError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1

    if not payload:
        print("invalid: empty payload", file=sys.stderr)
        return 1

    version, body = payload[0], payload[1:]
    if version in (MAINNET_WIF, TESTNET_WIF):
        try:
            key = decode_wif(args.address)
        except ValueError as e:
            kind = "testnet WIF" if version == TESTNET_WIF else "mainnet WIF"
            print(f"version: 0x{version:02x} ({kind})")
            print(f"payload: {body.hex()}")
            print(f"invalid: {e}", file=sys.stderr)
            return 1
        kind = "testnet WIF" if key.testnet else "mainnet WIF"
        print(f"version: 0x{version:02x} ({kind})")
        print(f"private key: {key.private_key.hex()}")
        print(f"compressed: {'yes' if key.compressed else 'no'}")
        return 0

    kind = VERSIONS.get(version, "unknown")
    print(f"version: 0x{version:02x} ({kind})")
    print(f"payload: {body.hex()}")
    if kind != "unknown" and len(body) != 20:
        print(f"warning: expected 20 byte hash, got {len(body)}", file=sys.stderr)
        return 1
    return 0


def cmd_wif_encode(args):
    try:
        print(encode_wif(args.private_key, compressed=not args.uncompressed, testnet=args.testnet))
    except ValueError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_wif_decode(args):
    try:
        key = decode_wif(args.wif)
    except (TypeError, ValueError) as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    print(f"private key: {key.private_key.hex()}")
    print(f"compressed: {'yes' if key.compressed else 'no'}")
    print(f"testnet: {'yes' if key.testnet else 'no'}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="btcbasics")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("hash", help="hash hex input")
    p.add_argument("algo", choices=["sha256", "sha256d", "hash160"])
    p.add_argument("data", type=parse_hex)
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("encode", help="base58check encode a hex payload")
    p.add_argument("payload", type=parse_hex)
    p.add_argument("--version", type=lambda v: int(v, 0),
                   help="version byte to prepend, e.g. 0x00")
    p.set_defaults(func=cmd_encode)

    p = sub.add_parser("decode", help="decode and validate a base58check string")
    p.add_argument("address")
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("wif", help="encode or decode a Wallet Import Format key")
    wif_sub = p.add_subparsers(dest="wif_command", required=True)
    pe = wif_sub.add_parser("encode", help="encode a 32-byte hex private key")
    pe.add_argument("private_key", type=parse_hex)
    pe.add_argument("--uncompressed", action="store_true",
                    help="omit the compressed-pubkey flag (WIF starts with 5)")
    pe.add_argument("--testnet", action="store_true")
    pe.set_defaults(func=cmd_wif_encode)
    pd = wif_sub.add_parser("decode", help="decode a WIF string")
    pd.add_argument("wif")
    pd.set_defaults(func=cmd_wif_decode)

    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
