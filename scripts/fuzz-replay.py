#!/usr/bin/env python3

import argparse
import hashlib
import socket
import struct
import sys
from pathlib import Path
from typing import NoReturn


def _bootstrap_jam_types_path() -> None:
    home = Path.home()
    venv_site = list((home / ".local" / "pip" / "jam-types" / "lib").glob("python*/site-packages"))
    if venv_site:
        sys.path.insert(0, str(venv_site[0]))


try:
    from jam_types import Header, ScaleBytes, spec  # type: ignore[import-not-found]
    from jam_types.fuzzer import (  # type: ignore[import-not-found]
        Block,
        FEATURES_MASK,
        FuzzerMessage,
        RawState,
        TraceStep,
    )
except ModuleNotFoundError:
    _bootstrap_jam_types_path()
    try:
        from jam_types import Header, ScaleBytes, spec  # type: ignore[import-not-found]
        from jam_types.fuzzer import (  # type: ignore[import-not-found]
            Block,
            FEATURES_MASK,
            FuzzerMessage,
            RawState,
            TraceStep,
        )
    except ModuleNotFoundError as exc:
        print(f"Error: failed to import jam_types: {exc}", file=sys.stderr)
        sys.exit(1)


# Feature flags for fuzz protocol
FEATURE_ANCESTRY = 0x00000001
FEATURE_FORKS = 0x00000002


def parse_features(features_str: str) -> int:
    """Parse comma-separated feature names into a bitmask integer."""
    if features_str.lower() == "none":
        return 0
    result = 0
    for name in features_str.split(","):
        name = name.strip().lower()
        if name == "ancestry":
            result |= FEATURE_ANCESTRY
        elif name == "forks":
            result |= FEATURE_FORKS
        else:
            raise ValueError(f"Unknown feature: {name!r}. Valid: ancestry, forks, none")
    return result


def parse_genesis(path: str) -> tuple[bytes, bytes, bytes]:
    blob = Path(path).read_bytes()
    sb = ScaleBytes(blob)

    Header(data=sb).process()
    header_bytes = blob[0:sb.offset]

    state_root = blob[sb.offset : sb.offset + 32]
    if len(state_root) != 32:
        raise ValueError(f"invalid genesis state_root length in {path}")
    sb.offset += 32

    keyvals_bytes = blob[sb.offset:]
    return header_bytes, keyvals_bytes, state_root




def parse_step_full(path: str) -> tuple[bytes, str, str, bytes, bytes]:
    blob = Path(path).read_bytes()
    sb = ScaleBytes(blob)

    RawState(data=sb).process()
    block_start = sb.offset
    pre_state_root_hex = "0x" + blob[0:32].hex()

    Block(data=sb).process()
    block_end = sb.offset
    block_bytes = blob[block_start:block_end]

    block_sb = ScaleBytes(block_bytes)
    Header(data=block_sb).process()
    header_bytes = block_bytes[0:block_sb.offset]

    post_start = sb.offset
    RawState(data=sb).process()
    post_state_bytes = blob[post_start:sb.offset]

    if len(post_state_bytes) < 32:
        raise ValueError(f"invalid post_state in {path}")
    expected_state_root_hex = "0x" + post_state_bytes[0:32].hex()
    post_keyvals_bytes = post_state_bytes[32:]

    import_block_wire = b"\x03" + block_bytes
    return import_block_wire, expected_state_root_hex, pre_state_root_hex, header_bytes, post_keyvals_bytes


def build_peer_info(features_mask: int) -> bytes:
    app_name = b"fuzz-replay"
    return b"".join(
        [
            b"\x00",
            b"\x01",
            struct.pack("<I", features_mask),
            bytes([0, 7, 2]),  # JAM protocol version: major=0, minor=7, patch=2
            bytes([0, 1, 27]),  # App version: major=0, minor=1, patch=27
            bytes([len(app_name)]),
            app_name,
        ]
    )


def parse_peer_info(data: bytes) -> dict:
    try:
        decoded = FuzzerMessage(data=ScaleBytes(data)).decode()
    except Exception:
        if len(data) < 2 or data[0] != 0:
            raise
        compat = bytes([data[0], data[1]]) + data[2:12] + bytes([data[12] >> 2]) + data[13:]  # compat: bits[2..8] hold the minor version, shift right to extract
        decoded = FuzzerMessage(data=ScaleBytes(compat)).decode()
    kind = next(iter(decoded.keys()), None)
    if kind != "peer_info":
        raise ValueError(f"expected peer_info, got {kind}")

    peer = decoded["peer_info"]
    if peer.get("fuzz_version") != 1:
        print(
            f"Warning: peer_info fuzz_version={peer.get('fuzz_version')} (expected 1)",
            file=sys.stderr,
        )
    return peer


def _fail(message: str) -> NoReturn:
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(1)


def _discover_trace(trace_dir: Path) -> tuple[list[Path], bool]:
    step_files = sorted(p for p in trace_dir.glob("[0-9]*.bin") if p.is_file())
    has_genesis = (trace_dir / "genesis.bin").is_file()
    return step_files, has_genesis


def send_msg(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack("<I", len(data)))
    sock.sendall(data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def recv_msg(sock: socket.socket) -> bytes:
    length_bytes = _recv_exact(sock, 4)
    n = struct.unpack("<I", length_bytes)[0]
    return _recv_exact(sock, n)


def _truncate_hex(hex_val: str) -> str:
    try:
        if not hex_val.startswith("0x"):
            return hex_val
        raw = bytes.fromhex(hex_val[2:])
    except Exception:
        return hex_val
    if len(raw) > 64:
        return hex_val[:34] + "..." + hex_val[-32:]  # keep 16 leading bytes + 16 trailing bytes of hex
    return hex_val


def _print_kv_diff(step_id: str, expected_kv: dict, actual_kv: dict) -> None:
    added_keys = sorted(k for k in actual_kv.keys() if k not in expected_kv)
    removed_keys = sorted(k for k in expected_kv.keys() if k not in actual_kv)
    changed_keys = sorted(
        k for k in expected_kv.keys() if k in actual_kv and expected_kv[k] != actual_kv[k]
    )

    print(f"State diff at step {step_id}:")
    print(f"  Added keys (in target, not expected): {len(added_keys)}")
    for key in added_keys:
        print(f"    + {key} = {_truncate_hex(str(actual_kv[key]))}")

    print(f"  Removed keys (expected, not in target): {len(removed_keys)}")
    for key in removed_keys:
        print(f"    - {key} = {_truncate_hex(str(expected_kv[key]))}")

    print(f"  Changed values: {len(changed_keys)}")
    for key in changed_keys:
        expected_val = _truncate_hex(str(expected_kv[key]))
        actual_val = _truncate_hex(str(actual_kv[key]))
        print(f"    ~ {key} expected: {expected_val} actual: {actual_val}")


def connect_socket(sock_path: str) -> socket.socket:
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
        return sock
    except Exception as exc:
        _fail(f"Error connecting to socket '{sock_path}': {exc}")


def replay_trace(trace_dir: Path, sock_path: str, spec_name: str, features_mask: int) -> int:
    step_files, has_genesis = _discover_trace(trace_dir)
    if step_files:
        first = step_files[0].name.rsplit(".", 1)[0]
        last = step_files[-1].name.rsplit(".", 1)[0]
    else:
        first = "--------"
        last = "--------"

    print(
        f"Trace: {trace_dir} | spec: {spec_name} | features: 0x{features_mask:08x} | "
        f"genesis: {'YES' if has_genesis else 'NO'} | steps: {len(step_files)} ({first} - {last})"
    )

    mismatches = 0
    passed = 0

    sock = connect_socket(sock_path)
    print(f"Connected to target socket: {sock_path}")
    try:
        send_msg(sock, build_peer_info(features_mask))
        peer = parse_peer_info(recv_msg(sock))
        negotiated = features_mask & int(peer.get("fuzz_features", 0))
        print(f"Negotiated features: 0x{negotiated:08x}")

        genesis_file = trace_dir / "genesis.bin"
        if genesis_file.is_file():
            header_bytes, keyvals_bytes, genesis_state_root = parse_genesis(str(genesis_file))
            initialize_wire = b"\x01" + header_bytes + keyvals_bytes + b"\x00"
            expected_genesis_hex = "0x" + genesis_state_root.hex()

            send_msg(sock, initialize_wire)
            init_msg = FuzzerMessage(data=ScaleBytes(recv_msg(sock))).decode()
            init_kind = next(iter(init_msg.keys()), None)
            if init_kind == "state_root":
                actual = init_msg["state_root"]
                if actual != expected_genesis_hex:
                    mismatches += 1
                    print(
                        "Initialize: ✗ state root MISMATCH "
                        f"(expected: {expected_genesis_hex}, got: {actual})"
                    )
                else:
                    print("Initialize: ✓ state root matches")
            elif init_kind == "error":
                mismatches += 1
                print(f"Warning: Initialize returned Error: {init_msg['error']}", file=sys.stderr)
            else:
                mismatches += 1
                print(f"Warning: Initialize returned unexpected response kind: {init_kind}", file=sys.stderr)
        else:
            if not step_files:
                print("Error: no step files found and no genesis.bin — cannot initialize", file=sys.stderr)
                return 1
            print("No genesis.bin — constructing Initialize from first step's pre-state")
            # Extract real header bytes from first step's block (NOT synthetic zeros)
            _, _, _, header_bytes, _ = parse_step_full(str(step_files[0]))
            # Extract pre_state keyvals from first step
            first_blob = step_files[0].read_bytes()
            first_sb = ScaleBytes(first_blob)
            RawState(data=first_sb).process()
            pre_state_bytes = first_blob[0:first_sb.offset]
            pre_state_root_bytes = pre_state_bytes[0:32]
            pre_state_keyvals_bytes = pre_state_bytes[32:]
            initialize_wire = b"\x01" + header_bytes + pre_state_keyvals_bytes + b"\x00"
            expected_pre_state_root_hex = "0x" + pre_state_root_bytes.hex()

            send_msg(sock, initialize_wire)
            init_msg = FuzzerMessage(data=ScaleBytes(recv_msg(sock))).decode()
            init_kind = next(iter(init_msg.keys()), None)
            if init_kind == "state_root":
                actual = init_msg["state_root"]
                if actual != expected_pre_state_root_hex:
                    mismatches += 1
                    print(
                        "Initialize: ✗ state root MISMATCH "
                        f"(expected: {expected_pre_state_root_hex}, got: {actual})"
                    )
                else:
                    print("Initialize: ✓ state root matches (synthetic)")
            elif init_kind == "error":
                mismatches += 1
                print(f"Warning: Initialize returned Error: {init_msg['error']}", file=sys.stderr)
            else:
                mismatches += 1
                print(f"Warning: Initialize returned unexpected response kind: {init_kind}", file=sys.stderr)

        for step_file in step_files:
            import_block_wire, expected_state_root_hex, pre_state_root_hex, header_bytes, _post_keyvals_bytes = parse_step_full(
                str(step_file)
            )
            step_id = step_file.stem

            send_msg(sock, import_block_wire)
            response = FuzzerMessage(data=ScaleBytes(recv_msg(sock))).decode()
            kind = next(iter(response.keys()), None)

            if kind == "state_root":
                got = response["state_root"]
                if got == expected_state_root_hex:
                    passed += 1
                    print(f"Step {step_id}: ✓ state root matches")
                else:
                    mismatches += 1
                    print(
                        f"Step {step_id}: ✗ state root MISMATCH "
                        f"(expected: {expected_state_root_hex}, got: {got})"
                    )
                    header_hash = hashlib.blake2b(header_bytes, digest_size=32).digest()
                    send_msg(sock, b"\x04" + header_hash)
                    state_msg = FuzzerMessage(data=ScaleBytes(recv_msg(sock))).decode()
                    state_kind = next(iter(state_msg.keys()), None)
                    if state_kind != "state":
                        print(
                            f"Warning: Step {step_id} GetState returned unexpected response kind: {state_kind}",
                            file=sys.stderr,
                        )
                    else:
                        actual_kv = {str(kv["key"]): str(kv["value"]) for kv in state_msg["state"]}
                        ts = TraceStep(data=ScaleBytes(step_file.read_bytes())).decode()
                        expected_kv = {
                            str(kv["key"]): str(kv["value"])
                            for kv in ts["post_state"]["keyvals"]
                        }
                        _print_kv_diff(step_id, expected_kv, actual_kv)
            elif kind == "error":
                # Target rejected the block — valid if state didn't change (pre == post)
                if pre_state_root_hex == expected_state_root_hex:
                    passed += 1
                    print(f"Step {step_id}: ✓ block rejected (error), state root unchanged (pre == post)")
                else:
                    mismatches += 1
                    print(
                        f"Step {step_id}: ✗ block rejected (error) but state should have changed "
                        f"(pre: {pre_state_root_hex}, expected post: {expected_state_root_hex})",
                        file=sys.stderr,
                    )
            else:
                mismatches += 1
                print(
                    f"Warning: Step {step_id} unexpected response kind: {kind}",
                    file=sys.stderr,
                )

        print(f"{len(step_files)} steps replayed, {passed} passed, {mismatches} failed")
        return 1 if mismatches else 0
    finally:
        sock.close()
        print("Connection closed")


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay JAM fuzzer trace binaries")
    parser.add_argument("--trace-dir", required=True, help="Trace directory path")
    parser.add_argument(
        "--sock",
        "--target-sock",
        dest="sock",
        required=True,
        help="Target UNIX socket path",
    )
    parser.add_argument("--spec", default="tiny", choices=["tiny", "full"], help="JAM spec")
    parser.add_argument(
        "--features",
        default="ancestry,forks",
        help="Comma-separated fuzz features to advertise: ancestry, forks, none (default: ancestry,forks)",
    )

    args = parser.parse_args()
    spec.set_spec(args.spec)

    try:
        features_mask = parse_features(args.features)
    except ValueError as exc:
        _fail(str(exc))

    trace_dir = Path(args.trace_dir)
    if not trace_dir.exists():
        _fail(f"trace dir does not exist: {trace_dir}")
    if not trace_dir.is_dir():
        _fail(f"trace dir is not a directory: {trace_dir}")

    code = replay_trace(trace_dir, args.sock, args.spec, features_mask)
    sys.exit(code)

if __name__ == "__main__":
    main()
