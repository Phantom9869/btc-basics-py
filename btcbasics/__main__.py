import argparse
import json
import sys

from .address import address_to_scriptpubkey, decode_segwit_address, identify_address, p2pkh_address, p2sh_address, p2tr_address, p2wpkh_address, p2wsh_address, scriptpubkey_to_address, segwit_script_type
from .base58 import b58decode_check, b58encode_check
from .hashes import hash160, sha256, sha256d
from .message import signed_message_hash
from .varint import decode_compact_size, encode_compact_size
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


def parse_int(text):
    raw = text.strip()
    try:
        return int(raw, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a valid integer: {text}")


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


def _segwit_type(info) -> str:
    name = segwit_script_type(info.version, info.program)
    if name == "witness":
        return f"witness v{info.version}"
    return name.upper()


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
        typ = f"{network} {_segwit_type(info)}"
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
        "p2tr": p2tr_address,
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


def _address_info_data(info):
    data = {"valid": info.valid, "type": info.type}
    if info.network is not None:
        data["network"] = info.network
    if info.type == "wif" and info.payload is not None:
        data["private_key"] = info.payload.hex()
        if info.compressed is not None:
            data["compressed"] = info.compressed
    elif info.type in ("p2wpkh", "p2wsh", "p2tr", "witness") and info.payload is not None:
        data["witness_version"] = info.version
        data["program"] = info.payload.hex()
    elif info.payload is not None:
        data["payload"] = info.payload.hex()
        if info.version is not None:
            data["version"] = info.version
    if info.error:
        data["error"] = info.error
    return data


def _address_info_text(info):
    typ = info.type
    if typ == "witness" and info.version is not None:
        typ = f"witness v{info.version}"
    lines = [
        f"valid: {'yes' if info.valid else 'no'}",
        f"type: {typ}",
    ]
    if info.network:
        lines.append(f"network: {info.network}")
    if info.type == "wif" and info.payload is not None:
        lines.append(f"private key: {info.payload.hex()}")
        if info.compressed is not None:
            lines.append(f"compressed: {'yes' if info.compressed else 'no'}")
    elif info.type in ("p2wpkh", "p2wsh", "p2tr", "witness") and info.payload is not None:
        lines.append(f"witness version: {info.version}")
        lines.append(f"program: {info.payload.hex()}")
    elif info.payload is not None:
        if info.version is not None:
            lines.append(f"version: 0x{info.version:02x}")
        lines.append(f"payload: {info.payload.hex()}")
    if info.error:
        lines.append(f"error: {info.error}")
    return "\n".join(lines)


def cmd_validate(args):
    info = identify_address(args.address)
    _emit(args, text=_address_info_text(info), data=_address_info_data(info))
    return 0 if info.valid else 1


def cmd_scriptpubkey(args):
    if args.address and args.script is not None:
        print("give an address or --from-script, not both", file=sys.stderr)
        return 1
    if args.address is None and args.script is None:
        print("an address or --from-script is required", file=sys.stderr)
        return 1
    if args.script is not None:
        try:
            addr = scriptpubkey_to_address(args.script, testnet=args.testnet)
        except ValueError as e:
            print(f"invalid: {e}", file=sys.stderr)
            return 1
        _emit(args, text=addr, data={"address": addr, "testnet": args.testnet})
        return 0
    try:
        script = address_to_scriptpubkey(args.address)
    except (TypeError, ValueError) as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    _emit(args, text=script.hex(), data={"scriptpubkey": script.hex()})
    return 0


def cmd_varint_encode(args):
    try:
        encoded = encode_compact_size(args.value).hex()
    except ValueError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    _emit(args, text=encoded, data={"value": args.value, "encoded": encoded})


def cmd_varint_decode(args):
    try:
        value, rest = decode_compact_size(args.data)
    except (TypeError, ValueError) as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    if rest:
        print("invalid: trailing data after compact size", file=sys.stderr)
        return 1
    _emit(args, text=str(value), data={"value": value, "encoded": args.data.hex()})


def cmd_message_hash(args):
    digest = signed_message_hash(args.message).hex()
    _emit(args, text=digest, data={"message": args.message, "hash": digest})


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

    p = sub.add_parser("decode", parents=[shared], help="decode and validate a Base58Check or SegWit v0-v16 address")
    p.add_argument("address")
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("address", parents=[shared], help="build a P2PKH, P2SH, SegWit v0 or Taproot address")
    p.add_argument("kind", choices=["p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr"])
    p.add_argument("data", type=parse_hex,
                   help="HASH160, script hash, x-only pubkey, or for p2pkh/p2wpkh a public key")
    p.add_argument("--testnet", action="store_true")
    p.set_defaults(func=cmd_address)

    p = sub.add_parser("scriptpubkey", parents=[shared], help="convert between an address and its scriptPubKey")
    p.add_argument("address", nargs="?", help="payment address to encode as a scriptPubKey")
    p.add_argument("--from-script", type=parse_hex, dest="script",
                   help="scriptPubKey hex to decode into an address")
    p.add_argument("--testnet", action="store_true",
                   help="with --from-script, build a testnet address")
    p.set_defaults(func=cmd_scriptpubkey)

    p = sub.add_parser("validate", parents=[shared], help="identify an address or WIF key and check it")
    p.add_argument("address")
    p.set_defaults(func=cmd_validate)

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

    p = sub.add_parser("varint", parents=[shared], help="encode or decode a Bitcoin CompactSize varint")
    varint_sub = p.add_subparsers(dest="varint_command", required=True)
    pe = varint_sub.add_parser("encode", parents=[shared], help="encode an integer as a compact size")
    pe.add_argument("value", type=parse_int)
    pe.set_defaults(func=cmd_varint_encode)
    pd = varint_sub.add_parser("decode", parents=[shared], help="decode compact-size hex")
    pd.add_argument("data", type=parse_hex)
    pd.set_defaults(func=cmd_varint_decode)

    p = sub.add_parser("message-hash", parents=[shared],
                       help="hash a Bitcoin signed message (magic prefix + compact-size length)")
    p.add_argument("message", help="message text, encoded as UTF-8")
    p.set_defaults(func=cmd_message_hash)

    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
