import argparse
import json
import sys

from .address import decode_segwit_address, p2pkh_address, p2sh_address, p2wpkh_address, p2wsh_address
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


def _emit(args, text=None, data=None):
    if getattr(args, "json", False):
        print(json.dumps(data))
    elif text is not None:
        print(text)
    else:
        for key, value in data.items():
            if isinstance(value, bool):
                value = "yes" if value else "no"
            print(f"{key.replace('_', ' ')}: {value}")


def cmd_hash(args):
    funcs = {"sha256": sha256, "sha256d": sha256d, "hash160": hash160}
    digest = funcs[args.algo](args.data).hex()
    _emit(args, text=digest, data={"algo": args.algo, "digest": digest})


def cmd_encode(args):
    payload = args.payload
    if args.version is not None:
        if not 0 <= args.version <= 0xFF:
            print("version must fit in one byte", file=sys.stderr)
            return 1
        payload = bytes([args.version]) + payload
    encoded = b58encode_check(payload)
    _emit(args, text=encoded, data={"encoded": encoded})


def _looks_like_segwit(addr: str) -> bool:
    prefix = addr.strip()[:3].lower()
    return prefix in ("bc1", "tb1")


def cmd_decode(args):
    if _looks_like_segwit(args.address):
        try:
            info = decode_segwit_address(args.address)
        except (TypeError, ValueError) as e:
            print(f"invalid: {e}", file=sys.stderr)
            return 1
        network = "testnet" if info.hrp == "tb" else "mainnet"
        kind = "P2WPKH" if len(info.program) == 20 else "P2WSH"
        typ = f"{network} {kind}"
        _emit(
            args,
            text=f"hrp: {info.hrp} ({typ})\nwitness version: {info.version}\nprogram: {info.program.hex()}",
            data={
                "type": typ,
                "hrp": info.hrp,
                "witness_version": info.version,
                "program": info.program.hex(),
            },
        )
        return 0

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
        _emit(
            args,
            text=(
                f"version: 0x{version:02x} ({kind})\n"
                f"private key: {key.private_key.hex()}\n"
                f"compressed: {'yes' if key.compressed else 'no'}"
            ),
            data={
                "type": kind,
                "version": version,
                "private_key": key.private_key.hex(),
                "compressed": key.compressed,
            },
        )
        return 0

    kind = VERSIONS.get(version, "unknown")
    _emit(
        args,
        text=f"version: 0x{version:02x} ({kind})\npayload: {body.hex()}",
        data={"type": kind, "version": version, "payload": body.hex()},
    )
    if kind != "unknown" and len(body) != 20:
        print(f"warning: expected 20 byte hash, got {len(body)}", file=sys.stderr)
        return 1
    return 0


def cmd_address(args):
    builders = {
        "p2pkh": p2pkh_address,
        "p2sh": p2sh_address,
        "p2wpkh": p2wpkh_address,
        "p2wsh": p2wsh_address,
    }
    try:
        addr = builders[args.kind](args.data, testnet=args.testnet)
    except ValueError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    _emit(args, text=addr, data={"address": addr, "type": args.kind, "testnet": args.testnet})
    return 0


def cmd_wif_encode(args):
    try:
        wif = encode_wif(args.private_key, compressed=not args.uncompressed, testnet=args.testnet)
    except ValueError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    _emit(
        args,
        text=wif,
        data={
            "wif": wif,
            "compressed": not args.uncompressed,
            "testnet": args.testnet,
        },
    )
    return 0


def cmd_wif_decode(args):
    try:
        key = decode_wif(args.wif)
    except (TypeError, ValueError) as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    _emit(
        args,
        text=(
            f"private key: {key.private_key.hex()}\n"
            f"compressed: {'yes' if key.compressed else 'no'}\n"
            f"testnet: {'yes' if key.testnet else 'no'}"
        ),
        data={
            "private_key": key.private_key.hex(),
            "compressed": key.compressed,
            "testnet": key.testnet,
        },
    )
    return 0


def main(argv=None):
    shared = argparse.ArgumentParser(add_help=False)
    # default=SUPPRESS so a --json before the subcommand is not
    # overwritten by the same flag's False default on the subparser.
    shared.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="print machine-readable JSON instead of text")
    parser = argparse.ArgumentParser(prog="btcbasics", parents=[shared])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("hash", parents=[shared], help="hash hex input")
    p.add_argument("algo", choices=["sha256", "sha256d", "hash160"])
    p.add_argument("data", type=parse_hex)
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("encode", parents=[shared], help="base58check encode a hex payload")
    p.add_argument("payload", type=parse_hex)
    p.add_argument("--version", type=lambda v: int(v, 0),
                   help="version byte to prepend, e.g. 0x00")
    p.set_defaults(func=cmd_encode)

    p = sub.add_parser("decode", parents=[shared], help="decode and validate a Base58Check or SegWit address")
    p.add_argument("address")
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("address", parents=[shared], help="build a P2PKH, P2SH or SegWit v0 address")
    p.add_argument("kind", choices=["p2pkh", "p2sh", "p2wpkh", "p2wsh"])
    p.add_argument("data", type=parse_hex,
                   help="HASH160, script hash, or for p2pkh/p2wpkh a public key")
    p.add_argument("--testnet", action="store_true")
    p.set_defaults(func=cmd_address)

    p = sub.add_parser("wif", parents=[shared], help="encode or decode a Wallet Import Format key")
    wif_sub = p.add_subparsers(dest="wif_command", required=True)
    pe = wif_sub.add_parser("encode", parents=[shared], help="encode a 32-byte hex private key")
    pe.add_argument("private_key", type=parse_hex)
    pe.add_argument("--uncompressed", action="store_true",
                    help="omit the compressed-pubkey flag (WIF starts with 5)")
    pe.add_argument("--testnet", action="store_true")
    pe.set_defaults(func=cmd_wif_encode)
    pd = wif_sub.add_parser("decode", parents=[shared], help="decode a WIF string")
    pd.add_argument("wif")
    pd.set_defaults(func=cmd_wif_decode)

    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
