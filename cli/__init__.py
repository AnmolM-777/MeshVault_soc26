"""
MeshVault CLI Package.
Provides high-level commands for splitting secrets and recovering them from peers.
"""

from cli.split import execute_split
from cli.recover import execute_recover

__all__ = ["execute_split", "execute_recover"]
