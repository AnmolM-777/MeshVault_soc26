from unittest.mock import MagicMock, patch
from network.discovery import PeerDiscovery, _get_local_ip


def test_get_local_ip_returns_valid_string():
    ip = _get_local_ip()
    assert isinstance(ip, str)
    assert len(ip.split(".")) == 4


def test_peer_discovery_initialization():
    pd = PeerDiscovery()
    assert pd.service_type == "_meshvault._tcp.local."
    assert pd.zeroconf is None
    assert pd.service_info is None


@patch("network.discovery.Zeroconf")
def test_advertise_service_mocked(mock_zc_class):
    mock_zc = MagicMock()
    mock_zc_class.return_value = mock_zc

    pd = PeerDiscovery()
    pd.advertise_service(
        name="node1",
        port=5000,
        metadata={"k": "3", "n": "5"},
        host_ip="192.168.1.10",
    )

    assert pd.service_info is not None
    assert pd.service_info.port == 5000
    assert mock_zc.register_service.called

    pd.stop()
    assert mock_zc.unregister_service.called
    assert mock_zc.close.called


@patch("network.discovery.ServiceBrowser")
@patch("network.discovery.Zeroconf")
def test_find_peers_mocked(mock_zc_class, mock_browser_class):
    mock_zc = MagicMock()
    mock_zc_class.return_value = mock_zc

    pd = PeerDiscovery()

    # Simulate discovered service
    def simulate_browse(zc, type_, listener):
        mock_info = MagicMock()
        mock_info.name = "node2._meshvault._tcp.local."
        mock_info.addresses = [b"\xc0\xa8\x01\x14"]  # 192.168.1.20
        mock_info.port = 6000
        mock_info.properties = {b"k": b"2", b"n": b"3"}
        mock_info.parsed_addresses.return_value = ["192.168.1.20"]
        listener.discovered_infos.append(mock_info)
        return MagicMock()

    mock_browser_class.side_effect = simulate_browse

    peers = pd.find_peers(timeout_seconds=0.01)
    assert len(peers) == 1
    assert peers[0]["host"] == "192.168.1.20"
    assert peers[0]["port"] == 6000
    assert peers[0]["properties"] == {"k": "2", "n": "3"}

    pd.stop()
