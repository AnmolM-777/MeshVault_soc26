import pytest
import socket
from unittest.mock import patch, MagicMock
from network.discovery import PeerDiscovery, PeerListener


# PeerListener Tests --

def test_add_service():
    """Peer mila → list mein add hona chahiye."""
    # listener object banao
    listener = PeerListener()

    # fake zeroconf banao
    mock_zeroconf = MagicMock()

    # fake peer info banao
    mock_info = MagicMock()
    mock_info.addresses = [socket.inet_aton("192.168.1.5")]  # fake IP
    mock_info.port = 5000                                     # fake port
    mock_info.properties = {b"version": b"1.0"}              # fake metadata

    # fake zeroconf ko batao yeh info return karo
    mock_zeroconf.get_service_info.return_value = mock_info

    # function call karo
    listener.add_service(mock_zeroconf, "_meshvault._tcp.local.", "Deepak-PC._meshvault._tcp.local.")

    # verify karo
    assert len(listener.peers) == 1                                    # ek peer add hua?
    assert listener.peers[0]["ip"] == "192.168.1.5"                   # IP sahi?
    assert listener.peers[0]["port"] == 5000                           # port sahi?
    assert listener.peers[0]["metadata"] == {"version": "1.0"}        # metadata sahi?


def test_add_service_none_info():
    """None info aaya → kuch add nahi hona chahiye."""
    # listener object banao
    listener = PeerListener()

    # fake zeroconf banao jo None return kare
    mock_zeroconf = MagicMock()
    mock_zeroconf.get_service_info.return_value = None

    # function call karo
    listener.add_service(mock_zeroconf, "_meshvault._tcp.local.", "Unknown._meshvault._tcp.local.")

    # kuch add nahi hona chahiye
    assert len(listener.peers) == 0


def test_remove_service():
    """Peer remove kiya → list se hata hona chahiye."""
    # listener object banao
    listener = PeerListener()

    # manually ek peer add karo list mein
    listener.peers = [{
        "name": "Deepak-PC._meshvault._tcp.local.",
        "ip": "192.168.1.5",
        "port": 5000,
        "metadata": {}
    }]

    # peer remove karo
    listener.remove_service(MagicMock(), "_meshvault._tcp.local.", "Deepak-PC._meshvault._tcp.local.")

    # list khaali honi chahiye
    assert len(listener.peers) == 0


def test_no_duplicate_peers():
    """Same peer do baar add kiya → sirf ek hona chahiye."""
    # listener object banao
    listener = PeerListener()

    # fake zeroconf aur info banao
    mock_zeroconf = MagicMock()
    mock_info = MagicMock()
    mock_info.addresses = [socket.inet_aton("192.168.1.5")]
    mock_info.port = 5000
    mock_info.properties = {b"version": b"1.0"}
    mock_zeroconf.get_service_info.return_value = mock_info

    # same peer do baar add karo
    listener.add_service(mock_zeroconf, "_meshvault._tcp.local.", "Deepak-PC._meshvault._tcp.local.")
    listener.add_service(mock_zeroconf, "_meshvault._tcp.local.", "Deepak-PC._meshvault._tcp.local.")

    # sirf ek hona chahiye
    assert len(listener.peers) == 1


# PeerDiscovery Tests ---

def test_advertise_service():
    """advertise_service → zeroconf aur service_info set hone chahiye."""
    # Zeroconf, ServiceInfo aur gethostbyname ko patch karo
    with patch("network.discovery.Zeroconf") as MockZeroconf, \
         patch("network.discovery.ServiceInfo") as MockServiceInfo, \
         patch("socket.gethostbyname", return_value="192.168.1.5"):

        # discovery object banao
        discovery = PeerDiscovery()

        # function call karo
        discovery.advertise_service("Deepak-PC", 5000, {"version": "1.0"})

        # verify karo
        assert MockZeroconf.called                  # Zeroconf banaya?
        assert MockServiceInfo.called               # ServiceInfo banaya?
        assert discovery.zeroconf is not None       # zeroconf set hua?
        assert discovery.service_info is not None   # service_info set hua?


def test_find_peers_with_peer():
    """find_peers → peer mila → list mein hona chahiye."""
    # fake listener banao jisme peer pehle se hai
    mock_listener = MagicMock()
    mock_listener.peers = [{
        "name": "Deepak-PC._meshvault._tcp.local.",
        "ip": "192.168.1.5",
        "port": 5000,
        "metadata": {}
    }]

    # Zeroconf, PeerListener, ServiceBrowser aur sleep patch karo
    with patch("network.discovery.Zeroconf"), \
         patch("network.discovery.PeerListener", return_value=mock_listener), \
         patch("network.discovery.ServiceBrowser"), \
         patch("time.sleep"):

        # discovery object banao
        discovery = PeerDiscovery()

        # function call karo
        peers = discovery.find_peers(timeout_seconds=0)

        # verify karo
        assert isinstance(peers, list)          # list return hua?
        assert len(peers) == 1                  # ek peer mila?
        assert peers[0]["ip"] == "192.168.1.5"  # IP sahi?
        assert peers[0]["port"] == 5000         # port sahi?


def test_find_peers_empty():
    """find_peers → koi peer nahi → empty list."""
    # Zeroconf, ServiceBrowser aur sleep patch karo
    with patch("network.discovery.Zeroconf"), \
         patch("network.discovery.ServiceBrowser"), \
         patch("time.sleep"):

        # discovery object banao
        discovery = PeerDiscovery()

        # function call karo
        peers = discovery.find_peers(timeout_seconds=0)

        # verify karo
        assert isinstance(peers, list)   # list return hua?
        assert len(peers) == 0           # khaali honi chahiye?


def test_stop():
    """stop → zeroconf aur service_info None ho jaane chahiye."""
    # Zeroconf, ServiceInfo aur gethostbyname patch karo
    with patch("network.discovery.Zeroconf"), \
         patch("network.discovery.ServiceInfo"), \
         patch("socket.gethostbyname", return_value="192.168.1.5"):

        # discovery object banao
        discovery = PeerDiscovery()

        # pehle advertise karo
        discovery.advertise_service("Deepak-PC", 5000)

        # ab stop karo
        discovery.stop()

        # dono None hone chahiye
        assert discovery.zeroconf is None       # zeroconf reset hua?
        assert discovery.service_info is None   # service_info reset hua?