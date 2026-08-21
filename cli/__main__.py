"""
MeshVault CLI Entrypoint.
"""

from __future__ import annotations

import argparse
import sys
from cli.recover import execute_recover
from cli.split import execute_split


def _parse_peer(peer_str: str) -> tuple[str, int]:
    """Parse 'host:port' string into (host, port) tuple."""
    parts = peer_str.strip().rsplit(":", 1)
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(
            f"Invalid peer format '{peer_str}'. Expected host:port (e.g. 192.168.1.50:5000)"
        )
    host, port_str = parts
    try:
        port = int(port_str)
        if port < 1 or port > 65535:
            raise ValueError()
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid port '{port_str}' in peer '{peer_str}'. Port must be an integer between 1 and 65535."
        )
    return (host, port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meshvault",
        description="MeshVault: Encrypted P2P Secret Sharing over LAN — No Server, No Cloud, No Trust Required.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Split sub-command
    split_parser = subparsers.add_parser(
        "split", help="Split a secret and distribute shares to LAN peers"
    )
    split_parser.add_argument(
        "-k",
        "--threshold",
        type=int,
        required=True,
        help="Threshold number of shares required to reconstruct (K)",
    )
    split_parser.add_argument(
        "-n",
        "--shares",
        type=int,
        required=True,
        help="Total number of shares to distribute (N)",
    )
    split_parser.add_argument(
        "-s",
        "--secret",
        type=str,
        help="Secret text (if omitted, will prompt or read from file)",
    )
    split_parser.add_argument(
        "-f", "--file", type=str, help="Path to file containing secret"
    )
    split_parser.add_argument(
        "-p",
        "--peer",
        action="append",
        type=_parse_peer,
        dest="peers",
        help="Explicit peer address in host:port format (can specify multiple times)",
    )
    split_parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout for peer discovery and socket connections in seconds (default: 5.0)",
    )

    # Recover sub-command
    recover_parser = subparsers.add_parser(
        "recover", help="Collect shares from LAN peers and recover the secret"
    )
    recover_parser.add_argument(
        "-k",
        "--threshold",
        type=int,
        required=True,
        help="Threshold number of shares required to reconstruct (K)",
    )
    recover_parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=5000,
        help="Local port to listen on for incoming peer shares (default: 5000)",
    )
    recover_parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Local interface host/IP to bind to (default: 0.0.0.0)",
    )
    recover_parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="File path to write recovered secret to (default: prints to stdout)",
    )
    recover_parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Socket timeout in seconds (default: wait indefinitely until K shares arrive)",
    )

    return parser


def _handle_split(args: argparse.Namespace) -> int:
    """Handle split CLI command."""
    secret_bytes: bytes = b""
    if args.file:
        try:
            with open(args.file, "rb") as f:
                secret_bytes = f.read()
        except OSError as e:
            print(f"Error reading secret file '{args.file}': {e}", file=sys.stderr)
            return 1
    elif args.secret is not None:
        secret_bytes = args.secret.encode("utf-8")
    else:
        import getpass

        try:
            prompt_secret = getpass.getpass("Enter secret to split: ")
            secret_bytes = prompt_secret.encode("utf-8")
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled.", file=sys.stderr)
            return 1

    if not secret_bytes:
        print("Error: Secret cannot be empty.", file=sys.stderr)
        return 1

    try:
        execute_split(
            secret=secret_bytes,
            threshold_k=args.threshold,
            shares_n=args.shares,
            peers=args.peers,
            discovery_timeout=args.timeout,
            transfer_timeout=args.timeout,
        )
        print("Split operation completed successfully.")
        return 0
    except Exception as e:
        print(f"Error during split: {e}", file=sys.stderr)
        return 1


def _handle_recover(args: argparse.Namespace) -> int:
    """Handle recover CLI command."""
    try:
        recovered_bytes = execute_recover(
            threshold_k=args.threshold,
            listen_port=args.port,
            listen_host=args.host,
            timeout=args.timeout,
        )
        if args.output:
            try:
                with open(args.output, "wb") as f:
                    f.write(recovered_bytes)
                print(f"Recovered secret written to {args.output}")
            except OSError as e:
                print(
                    f"Error writing recovered secret to '{args.output}': {e}",
                    file=sys.stderr,
                )
                return 1
        else:
            try:
                text = recovered_bytes.decode("utf-8")
                print(f"\n[***] Recovered Secret: {text}")
            except UnicodeDecodeError:
                print(f"\n[***] Recovered Binary Secret (Hex): {recovered_bytes.hex()}")
        return 0
    except Exception as e:
        print(f"Error during recover: {e}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "split":
        return _handle_split(args)
    elif args.command == "recover":
        return _handle_recover(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
