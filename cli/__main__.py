"""
MeshVault CLI Entrypoint.
"""

import sys
import argparse

def main():
    parser = argparse.ArgumentParser(
        description="MeshVault: Encrypted P2P Secret Sharing over LAN — No Server, No Cloud, No Trust Required."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Split sub-command
    split_parser = subparsers.add_parser("split", help="Split a secret and distribute shares to LAN peers")
    split_parser.add_argument("-k", "--threshold", type=int, required=True, help="Threshold number of shares required to reconstruct (K)")
    split_parser.add_argument("-n", "--shares", type=int, required=True, help="Total number of shares to distribute (N)")
    split_parser.add_argument("-s", "--secret", type=str, help="Secret text (if omitted, will prompt)")

    # Recover sub-command
    recover_parser = subparsers.add_parser("recover", help="Collect shares from LAN peers and recover the secret")
    recover_parser.add_argument("-k", "--threshold", type=int, required=True, help="Threshold number of shares required to reconstruct (K)")

    args = parser.parse_args()
    
    print("MeshVault Command Line Interface")
    print(f"Command selected: {args.command}")
    print("Implementation is currently in progress.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
