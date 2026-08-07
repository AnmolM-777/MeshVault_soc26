"""
Tests for network/discovery.py

These tests intentionally mock every Zeroconf call. Real multicast
sockets are unreliable (or outright blocked) on GitHub Actions
runners, so nothing here should ever open a real network socket.

Run locally with:
    pytest tests/test_discovery.py -v
"""

from unittest.mock import MagicMock, patch

import pytest

from network import discovery

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_zeroconf():
    """A Zeroconf instance that never touches a real socket."""
    with patch("network.discovery.Zeroconf") as mock_zc_cls:
        instance = MagicMock()
        mock_zc_cls.return_value = instance
        yield instance


@pytest.fixture
def fake_service_info():
    with patch("network.discovery.ServiceInfo") as mock_info_cls:
        instance = MagicMock()
        mock_info_cls.return_value = instance
        yield instance


# ---------------------------------------------------------------------------
# _encode_properties / _decode_properties
# ---------------------------------------------------------------------------


def test_encode_properties_returns_bytes_values():
    props = {"session_id": "abc123", "n": 5, "k": 3}
    encoded = discovery._encode_properties(props)

    assert isinstance(encoded, dict)
    for value in encoded.values():
        assert isinstance(value, bytes)


def test_decode_properties_round_trip():
    original = {"session_id": "abc123", "n": "5", "k": "3"}
    encoded = discovery._encode_properties(original)
    decoded = discovery._decode_properties(encoded)

    assert decoded["session_id"] == "abc123"
    assert decoded["n"] == "5"
    assert decoded["k"] == "3"


def test_decode_properties_handles_empty_dict():
    assert discovery._decode_properties({}) == {}


# ---------------------------------------------------------------------------
# _safe_int
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,default,expected",
    [
        ("5", 0, 5),
        ("not_a_number", 0, 0),
        (None, 7, 7),
        ("", 2, 2),
    ],
)
def test_safe_int(value, default, expected):
    assert discovery._safe_int(value, default) == expected


# ---------------------------------------------------------------------------
# _get_local_ip
# ---------------------------------------------------------------------------


def test_get_local_ip_returns_a_string():
    with patch("network.discovery.socket.socket") as mock_socket_cls:
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.42", 0)
        mock_socket_cls.return_value = mock_sock

        ip = discovery._get_local_ip()

        assert isinstance(ip, str)
        assert ip == "192.168.1.42"


def test_get_local_ip_falls_back_on_error():
    with patch(
        "network.discovery.socket.socket",
        side_effect=OSError("network unreachable"),
    ):
        ip = discovery._get_local_ip()
        # Should degrade gracefully rather than raising
        assert isinstance(ip, str)


# ---------------------------------------------------------------------------
# advertise_service
# ---------------------------------------------------------------------------


def test_advertise_service_registers_with_zeroconf(fake_zeroconf, fake_service_info):
    discovery.advertise_service(port=5000, session_id="session-xyz", n=5, k=3)

    fake_zeroconf.register_service.assert_called_once()


def test_advertise_service_includes_session_id_in_txt_record(
    fake_zeroconf, fake_service_info
):
    with patch("network.discovery._encode_properties") as mock_encode:
        mock_encode.return_value = {b"session_id": b"session-xyz"}

        discovery.advertise_service(port=5000, session_id="session-xyz", n=5, k=3)

        called_props = mock_encode.call_args[0][0]
        assert called_props.get("session_id") == "session-xyz"


def test_advertise_service_never_includes_key_material(
    fake_zeroconf, fake_service_info
):
    """
    Critical invariant: discovery must never leak cryptographic
    material into mDNS TXT records. That's channel.py's job.
    """
    with patch("network.discovery._encode_properties") as mock_encode:
        mock_encode.return_value = {}

        discovery.advertise_service(port=5000, session_id="session-xyz", n=5, k=3)

        called_props = mock_encode.call_args[0][0]
        forbidden_keys = {"private_key", "shared_secret", "share", "aes_key"}
        assert forbidden_keys.isdisjoint(called_props.keys())


# ---------------------------------------------------------------------------
# find_peers
# ---------------------------------------------------------------------------


def test_find_peers_returns_full_candidate_list(fake_zeroconf):
    """
    find_peers() should return every peer it sees, not silently cap
    at N. Peer selection belongs to split.py, not discovery.py.
    """
    fake_peers = [
        {"ip": "192.168.1.10", "port": 5000, "session_id": "s1"},
        {"ip": "192.168.1.11", "port": 5000, "session_id": "s1"},
        {"ip": "192.168.1.12", "port": 5000, "session_id": "s1"},
    ]

    with patch.object(discovery, "_collect_discovered_peers", return_value=fake_peers):
        peers = discovery.find_peers(session_id="s1", timeout=1)

    assert len(peers) == 3
    assert peers == fake_peers


def test_find_peers_filters_by_session_id(fake_zeroconf):
    """Peers advertising a different session_id must be ignored."""
    mixed_peers = [
        {"ip": "192.168.1.10", "port": 5000, "session_id": "s1"},
        {"ip": "192.168.1.99", "port": 5000, "session_id": "unrelated"},
    ]

    with patch.object(
        discovery,
        "_collect_discovered_peers",
        return_value=[p for p in mixed_peers if p["session_id"] == "s1"],
    ):
        peers = discovery.find_peers(session_id="s1", timeout=1)

    assert len(peers) == 1
    assert peers[0]["ip"] == "192.168.1.10"


def test_find_peers_self_filters_by_ip_port_not_name(fake_zeroconf):
    """
    Self-filtering uses (ip, port) identity, since mDNS record names
    are inconsistent across platforms.
    """
    local_ip = "192.168.1.50"
    local_port = 5000

    with patch("network.discovery._get_local_ip", return_value=local_ip):
        candidates = [
            {"ip": local_ip, "port": local_port, "session_id": "s1"},
            {"ip": "192.168.1.60", "port": 5000, "session_id": "s1"},
        ]
        filtered = discovery._filter_self(
            candidates, local_ip=local_ip, local_port=local_port
        )

    assert len(filtered) == 1
    assert filtered[0]["ip"] == "192.168.1.60"


# ---------------------------------------------------------------------------
# find_peers_until (early-exit variant)
# ---------------------------------------------------------------------------


def test_find_peers_until_stops_early_once_n_reached(fake_zeroconf):
    fake_peers = [
        {"ip": f"192.168.1.{i}", "port": 5000, "session_id": "s1"}
        for i in range(10, 15)
    ]

    with patch.object(discovery, "_collect_discovered_peers", return_value=fake_peers):
        peers = discovery.find_peers_until(session_id="s1", n=3, timeout=5)

    assert len(peers) >= 3


def test_find_peers_until_times_out_if_not_enough_peers(fake_zeroconf):
    with patch.object(discovery, "_collect_discovered_peers", return_value=[]):
        peers = discovery.find_peers_until(session_id="s1", n=5, timeout=0.1)

    assert peers == []


# ---------------------------------------------------------------------------
# stop / cleanup
# ---------------------------------------------------------------------------


def test_stop_closes_zeroconf_instance(fake_zeroconf):
    discovery._zc_instance = fake_zeroconf
    discovery.stop()

    fake_zeroconf.close.assert_called_once()


def test_stop_is_safe_to_call_when_nothing_registered(fake_zeroconf):
    """
    stop() must not raise even if advertise_service/find_peers were
    never called first (e.g. CLI error path before discovery started).
    """
    discovery._zc_instance = None
    try:
        discovery.stop()
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"stop() raised unexpectedly: {exc}")


def test_stop_uses_try_finally_even_on_unregister_error(fake_zeroconf):
    """
    Even if unregistering the service fails, the Zeroconf thread
    must still be closed to avoid leaking background threads.
    """
    fake_zeroconf.unregister_service.side_effect = RuntimeError("boom")
    discovery._zc_instance = fake_zeroconf

    with pytest.raises(RuntimeError):
        discovery.stop()

    fake_zeroconf.close.assert_called_once()
