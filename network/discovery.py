from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
import socket
import time
"""
Peer Discovery Module.
Uses Zeroconf (mDNS) to advertise and browse for MeshVault instances on the LAN.

Mentee C Deliverables:
- Weeks 1-2: Set up simple mDNS service advertisement and browsing using python-zeroconf.
- Weeks 3-4: Implement full mDNS announce/browse with metadata (N, K parameters inside TXT records).
"""
from typing import List, Dict

class PeerListener:
    def __init__(self):
        # Stores all discovered peers
        self.peers: List[Dict] = []

    def add_service(self, zeroconf, service_type: str, name: str) -> None:
        """
        Called automatically when a new MeshVault service is discovered.
        """
        info = zeroconf.get_service_info(service_type, name)

        if info is None:
            return

        # Convert IP bytes back to readable IP string
        ip = socket.inet_ntoa(info.addresses[0])

        # Decode TXT record (metadata)
        properties = {
            key.decode(): value.decode()
            for key, value in info.properties.items()
        }

        peer = {
            "name": name,
            "ip": ip,
            "port": info.port,
            "metadata": properties,
        }
        # Avoid duplicates
        if peer not in self.peers:
            self.peers.append(peer)

    def remove_service(self, zeroconf, service_type: str, name: str) -> None:
        """
        Called automatically when a service disappears from the network.
        """
        self.peers = [
            peer for peer in self.peers
            if peer["name"] != name
        ]

    def update_service(self, zeroconf, service_type: str, name: str) -> None:
        """
        Called automatically when a service updates its information.
        """
        self.remove_service(zeroconf, service_type, name)
        self.add_service(zeroconf, service_type, name)


class PeerDiscovery:
    """
    Registers the local service and browses for remote MeshVault peers.
    """

    def __init__(self, service_type: str = "_meshvault._tcp.local."):
        self.service_type = service_type
        self.zeroconf = None
        self.service_info = None

    def advertise_service(
        self, name: str, port: int, metadata: Dict[str, str] = None
    ) -> None:
        ip = socket.gethostbyname(socket.gethostname()) # Step 1- apna IP nikalo
        properties = metadata or {}                     # Step 2- metadata None hai to empty dict banao
        self.service_info = ServiceInfo(                # Step 3- ServiceInfo object banao
            type_=self.service_type,
            name=f"{name}.{self.service_type}",
            port=port,
            addresses=[socket.inet_aton(ip)],
            properties=properties
        )
        self.zeroconf = Zeroconf()   # Step 4 -Zeroconf object banao aur service register karo
        self.zeroconf.register_service(self.service_info)
        """
        Publishes the local peer service over mDNS with optional TXT records.

        Mentee C Weeks 1-4 Deliverable.
        """

    def find_peers(self, timeout_seconds: float = 5.0) -> List[Dict]:
        """
        Discovers active MeshVault services on the LAN and reads metadata.

        Mentee C Weeks 1-4 Deliverable.
        """
        if self.zeroconf is None:
            self.zeroconf = Zeroconf()
       
        listener = PeerListener()
        
        browser = ServiceBrowser(
        self.zeroconf,
        self.service_type,
        listener
        )

        time.sleep(timeout_seconds)
        return listener.peers

    def stop(self) -> None:
        """
        Stops advertising and browsing, cleaning up Zeroconf resources.
        """
        if self.zeroconf is not None:

        # Remove advertised service (if any)
            if self.service_info is not None:
                self.zeroconf.unregister_service(self.service_info)

        # Close Zeroconf
        self.zeroconf.close()

        # Reset references
        self.zeroconf = None
        self.service_info = None
