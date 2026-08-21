from __future__ import annotations

import socket
import time
from typing import Any, Dict, List
from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf


def _get_local_ip() -> str:
    """Detect local LAN IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


class _MeshVaultListener(ServiceListener):
    """Internal Zeroconf listener collecting discovered MeshVault service announcements."""

    def __init__(self):
        self.discovered_infos: list[ServiceInfo] = []

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            self.discovered_infos.append(info)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            self.discovered_infos.append(info)


class PeerDiscovery:
    """
    Registers the local service and browses for remote MeshVault peers via mDNS/Zeroconf.
    """

    def __init__(self, service_type: str = "_meshvault._tcp.local."):
        if not service_type.endswith("."):
            service_type += "."
        self.service_type = service_type
        self.zeroconf: Zeroconf | None = None
        self.service_info: ServiceInfo | None = None

    def _ensure_zeroconf(self) -> Zeroconf:
        if self.zeroconf is None:
            self.zeroconf = Zeroconf()
        return self.zeroconf

    def advertise_service(
        self,
        name: str,
        port: int,
        metadata: Dict[str, Any] | None = None,
        host_ip: str | None = None,
    ) -> None:
        """
        Publishes the local peer service over mDNS with optional TXT records.
        """
        zc = self._ensure_zeroconf()

        if host_ip is None:
            host_ip = _get_local_ip()

        service_name = f"{name}.{self.service_type}"
        props = {}
        if metadata:
            for k, v in metadata.items():
                props[str(k).encode("utf-8")] = str(v).encode("utf-8")

        self.service_info = ServiceInfo(
            type_=self.service_type,
            name=service_name,
            addresses=[socket.inet_aton(host_ip)],
            port=port,
            properties=props,
            server=f"{name}.local.",
        )
        zc.register_service(self.service_info)

    def find_peers(self, timeout_seconds: float = 3.0) -> List[Dict[str, Any]]:
        """
        Discovers active MeshVault services on the LAN and reads metadata.
        """
        zc = self._ensure_zeroconf()
        listener = _MeshVaultListener()
        browser = ServiceBrowser(zc, self.service_type, listener)

        time.sleep(timeout_seconds)
        browser.cancel()

        peers: List[Dict[str, Any]] = []
        for info in listener.discovered_infos:
            # Parse addresses
            host = None
            if info.addresses:
                try:
                    host = socket.inet_ntoa(info.addresses[0])
                except Exception:
                    host = None
            if not host and info.parsed_addresses():
                host = info.parsed_addresses()[0]

            # Decode properties
            props = {}
            if info.properties:
                for k, v in info.properties.items():
                    k_str = (
                        k.decode("utf-8", errors="ignore")
                        if isinstance(k, bytes)
                        else str(k)
                    )
                    v_str = (
                        v.decode("utf-8", errors="ignore")
                        if isinstance(v, bytes)
                        else str(v)
                    )
                    props[k_str] = v_str

            peers.append(
                {
                    "name": info.name,
                    "host": host or "127.0.0.1",
                    "port": info.port,
                    "properties": props,
                }
            )
        return peers

    def stop(self) -> None:
        """
        Stops advertising and browsing, cleaning up Zeroconf resources.
        """
        if self.zeroconf is not None:
            if self.service_info is not None:
                try:
                    self.zeroconf.unregister_service(self.service_info)
                except Exception:
                    pass
                self.service_info = None
            try:
                self.zeroconf.close()
            except Exception:
                pass
            self.zeroconf = None
