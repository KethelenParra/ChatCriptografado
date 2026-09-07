"""Teste do ChatRuntime em localhost, sem terminal interativo."""

from __future__ import annotations

import socket
import time
from queue import Empty, Queue

from services.chat_runtime import (
    STATUS_CONNECTED,
    ChatRuntime,
)


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _wait_for(predicate, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Tempo esgotado aguardando o estado esperado.")


def _drain(queue: Queue) -> list[dict]:
    items = []
    while True:
        try:
            items.append(queue.get_nowait())
        except Empty:
            return items


def test_alice_bob_runtime() -> None:
    port = _free_port()
    alice_events: Queue = Queue()
    bob_events: Queue = Queue()

    alice = ChatRuntime(
        role="alice",
        tcp_host="127.0.0.1",
        tcp_port=port,
        keys_dir="keys",
        event_queue=alice_events,
    )
    bob = ChatRuntime(
        role="bob",
        tcp_host="127.0.0.1",
        tcp_port=port,
        peer_host="127.0.0.1",
        keys_dir="test_keys/bob",
        event_queue=bob_events,
    )

    try:
        alice.start()
        _wait_for(lambda: alice.get_status()["connection_status"] == "waiting")
        bob.start()
        _wait_for(lambda: alice.get_status()["connection_status"] == STATUS_CONNECTED)
        _wait_for(lambda: bob.get_status()["connection_status"] == STATUS_CONNECTED)
        _wait_for(lambda: alice.get_status()["peer_key_received"])
        _wait_for(lambda: bob.get_status()["peer_key_received"])

        sent = alice.send_message("Olá Bob, teste do runtime.")
        assert sent["ciphertext_size"] == 512
        assert sent["original_in_tcp"] is False
        assert sent["algorithm"] == "RSA-4096"
        assert sent["padding"] == "OAEP"
        assert sent["hash"] == "SHA-256"

        def bob_got_message() -> bool:
            return any(
                item.get("type") == "message"
                and item.get("direction") == "received"
                and item.get("plaintext") == "Olá Bob, teste do runtime."
                for item in list(bob_events.queue)
            )

        _wait_for(bob_got_message)

        def alice_got_ack() -> bool:
            return any(
                item.get("type") == "message_ack"
                and item.get("message_id") == sent["message_id"]
                and item.get("status") == "decrypted"
                for item in list(alice_events.queue)
            )

        _wait_for(alice_got_ack)

        bob.send_message("Olá Alice, Bob responde pelo runtime.")

        def alice_got_reply() -> bool:
            return any(
                item.get("type") == "message"
                and item.get("direction") == "received"
                and item.get("plaintext") == "Olá Alice, Bob responde pelo runtime."
                for item in list(alice_events.queue)
            )

        _wait_for(alice_got_reply)

        print("========================================")
        print("     TESTE DO CHAT RUNTIME")
        print("========================================")
        print("Troca de chaves públicas: OK")
        print("Alice -> Bob: OK")
        print("ACK decrypted: OK")
        print("Bob -> Alice: OK")
        print("Ciphertext: 512 bytes")
        print("Plaintext no TCP: NÃO")
        print("Status: CHAT RUNTIME OK")
        print("========================================")
    finally:
        bob.disconnect()
        alice.disconnect()
        time.sleep(0.2)


if __name__ == "__main__":
    test_alice_bob_runtime()
