import pytest
from cli.__main__ import build_parser, _parse_peer, main


def test_parse_peer_valid():
    host, port = _parse_peer("192.168.1.100:5005")
    assert host == "192.168.1.100"
    assert port == 5005

    host, port = _parse_peer("localhost:8080")
    assert host == "localhost"
    assert port == 8080


def test_parse_peer_invalid():
    with pytest.raises(Exception):
        _parse_peer("invalid_peer_without_port")

    with pytest.raises(Exception):
        _parse_peer("127.0.0.1:99999")


def test_cli_split_parser():
    parser = build_parser()
    args = parser.parse_args(
        [
            "split",
            "-k",
            "3",
            "-n",
            "5",
            "-s",
            "mysecret",
            "-p",
            "127.0.0.1:5001",
            "-p",
            "127.0.0.1:5002",
        ]
    )
    assert args.command == "split"
    assert args.threshold == 3
    assert args.shares == 5
    assert args.secret == "mysecret"
    assert len(args.peers) == 2
    assert args.peers[0] == ("127.0.0.1", 5001)


def test_cli_recover_parser():
    parser = build_parser()
    args = parser.parse_args(
        ["recover", "-k", "3", "-p", "6000", "--host", "127.0.0.1", "-o", "out.txt"]
    )
    assert args.command == "recover"
    assert args.threshold == 3
    assert args.port == 6000
    assert args.host == "127.0.0.1"
    assert args.output == "out.txt"


def test_cli_split_main_execution(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("classified-top-secret")

    # Run split with file
    ret = main(
        ["split", "-k", "2", "-n", "3", "-f", str(secret_file), "--timeout", "0.1"]
    )
    assert ret == 0


def test_cli_split_invalid_k_n():
    ret = main(["split", "-k", "5", "-n", "3", "-s", "invalid"])
    assert ret == 1
