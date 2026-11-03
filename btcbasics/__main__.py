import argparse
import sys

from .base58 import b58decode_check, b58encode_check
from .hashes import hash160, sha256, sha256d

VERSIONS = {
    0x00: "mainnet P2PKH",
    0x05: "mainnet P2SH",
    0x6F: "testnet P2PKH",
    0xC4: "testnet P2SH",
}


def parse_hex(text):
    try:
        return bytes.fromhex(text)
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
    kind = VERSIONS.get(version, "unknown")
    print(f"version: 0x{version:02x} ({kind})")
    print(f"payload: {body.hex()}")
    if kind != "unknown" and len(body) != 20:
        print(f"warning: expected 20 byte hash, got {len(body)}", file=sys.stderr)
        return 1
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

    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
