"""Sessão de chat TCP + RSA, independente do terminal e do FastAPI.

Este serviço encapsula o socket, as chaves e a thread de recebimento.
A interface (React) só vê eventos JSON; o TCP entre Alice e Bob continua
sendo o canal remoto da atividade.

A chave privada permanece neste processo. A pública remota fica só em
memória. O plaintext nunca entra no pacote encrypted_message.
"""

from __future__ import annotations

import socket
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue
from typing import Any

from crypto.rsa_service import (
    RSA_CIPHERTEXT_BYTES,
    RSA_OAEP_SHA256_MAX_BYTES,
    RsaServiceError,
    base64_to_encrypted_bytes,
    decrypt_message_with_private_key,
    encrypt_message_with_public_key_object,
    encrypted_bytes_to_base64,
    load_public_key_from_pem,
    public_key_fingerprint,
    read_public_pem_text,
    validate_rsa_4096_public_key,
)
from network import resolve_keys_dir
from network.protocol import (
    PACKET_DISCONNECT,
    PACKET_ENCRYPTED_MESSAGE,
    PACKET_MESSAGE_ACK,
    PACKET_PUBLIC_KEY,
    ProtocolError,
    build_disconnect_packet,
    build_encrypted_message_packet,
    build_message_ack_packet,
    build_public_key_packet,
    receive_packet,
    send_packet,
)

STATUS_DISCONNECTED = "disconnected"
STATUS_WAITING = "waiting"
STATUS_CONNECTING = "connecting"
STATUS_CONNECTED = "connected"
STATUS_ERROR = "error"

ROLE_ALICE = "alice"
ROLE_BOB = "bob"

DISPLAY_NAMES = {ROLE_ALICE: "Alice", ROLE_BOB: "Bob"}


class ChatRuntimeError(Exception):
    """Erro operacional da sessão de chat."""


class ChatRuntime:
    """Controla uma ponta (Alice ou Bob) da conversa criptografada."""

    def __init__(
        self,
        role: str,
        tcp_port: int,
        keys_dir: str | Path,
        tcp_host: str = "0.0.0.0",
        peer_host: str | None = None,
        event_queue: Queue | None = None,
    ) -> None:
        normalized_role = role.strip().lower()
        if normalized_role not in DISPLAY_NAMES:
            raise ChatRuntimeError("O papel deve ser 'alice' ou 'bob'.")

        self.role = normalized_role
        self.local_user = DISPLAY_NAMES[normalized_role]
        self.peer_user = DISPLAY_NAMES[ROLE_BOB if normalized_role == ROLE_ALICE else ROLE_ALICE]
        self.tcp_host = tcp_host
        self.tcp_port = int(tcp_port)
        self.peer_host = peer_host
        self.keys_dir = resolve_keys_dir(keys_dir)
        self.private_key_path = self.keys_dir / "private_key.pem"
        self.public_key_path = self.keys_dir / "public_key.pem"
        self.events: Queue = event_queue if event_queue is not None else Queue()

        self._status = STATUS_DISCONNECTED
        self._status_lock = threading.Lock()
        self._socket_lock = threading.Lock()
        self._stop = threading.Event()
        self._server_socket: socket.socket | None = None
        self._connection: socket.socket | None = None
        self._worker: threading.Thread | None = None
        self._receiver: threading.Thread | None = None
        self._remote_public_key = None
        self._remote_fingerprint: str | None = None
        self._local_fingerprint: str | None = None
        self._local_key_loaded = False
        self._error_message: str | None = None

        self._load_local_keys()

    def _load_local_keys(self) -> None:
        if not self.private_key_path.exists() or not self.public_key_path.exists():
            raise ChatRuntimeError(
                f"As chaves locais não foram encontradas em: {self.keys_dir}"
            )
        pem = read_public_pem_text(self.public_key_path)
        self._local_fingerprint = public_key_fingerprint(pem)
        self._local_key_loaded = True

    def _set_status(self, status: str, error_message: str | None = None) -> None:
        with self._status_lock:
            self._status = status
            self._error_message = error_message
        self._emit_status()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _emit(self, event: dict[str, Any]) -> None:
        self.events.put(event)

    def _emit_status(self) -> None:
        snapshot = self.get_status()
        snapshot["type"] = "status"
        self._emit(snapshot)

    def _emit_error(self, message: str) -> None:
        self._emit({"type": "error", "message": message, "timestamp": self._now()})

    def get_status(self) -> dict[str, Any]:
        with self._status_lock:
            status = self._status
            error_message = self._error_message
        return {
            "connection_status": status,
            "local_user": self.local_user,
            "peer_user": self.peer_user,
            "role": self.role,
            "tcp_host": self.tcp_host,
            "tcp_port": self.tcp_port,
            "peer_host": self.peer_host,
            "local_key_loaded": self._local_key_loaded,
            "local_public_fingerprint": self._local_fingerprint,
            "peer_key_received": self._remote_public_key is not None,
            "peer_public_fingerprint": self._remote_fingerprint,
            "private_key_available": self.private_key_path.exists(),
            "error_message": error_message,
            "max_plaintext_bytes": RSA_OAEP_SHA256_MAX_BYTES,
            "algorithm": "RSA-4096",
            "padding": "OAEP",
            "hash": "SHA-256",
        }

    def start(self) -> None:
        """Alice escuta; Bob conecta. Não cifra ainda — só estabelece TCP + públicas."""
        if self.role == ROLE_ALICE:
            self._start_as_alice()
        else:
            self._start_as_bob()

    def _start_as_alice(self) -> None:
        if self._status in {STATUS_WAITING, STATUS_CONNECTED, STATUS_CONNECTING}:
            raise ChatRuntimeError("O servidor Alice já está em execução.")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.tcp_host, self.tcp_port))
            server.listen(1)
            server.settimeout(1.0)
        except OSError as error:
            server.close()
            self._set_status(STATUS_ERROR, str(error))
            raise ChatRuntimeError(
                f"Não foi possível iniciar o servidor TCP em {self.tcp_host}:{self.tcp_port}."
            ) from error

        self._server_socket = server
        self._stop.clear()
        self._set_status(STATUS_WAITING)
        self._worker = threading.Thread(target=self._accept_loop, daemon=True, name="alice-accept")
        self._worker.start()

    def _start_as_bob(self) -> None:
        if not self.peer_host:
            raise ChatRuntimeError("Bob precisa do endereço da Alice (--peer-host).")
        if self._status in {STATUS_CONNECTING, STATUS_CONNECTED}:
            raise ChatRuntimeError("O cliente Bob já está conectando ou conectado.")

        self._stop.clear()
        self._set_status(STATUS_CONNECTING)
        self._worker = threading.Thread(target=self._connect_loop, daemon=True, name="bob-connect")
        self._worker.start()

    def _accept_loop(self) -> None:
        assert self._server_socket is not None
        while not self._stop.is_set():
            try:
                connection, address = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                self._set_status(STATUS_ERROR, "Falha ao aceitar a conexão TCP.")
                return

            try:
                self._setup_connected_session(connection)
            except (ProtocolError, RsaServiceError, ChatRuntimeError, OSError) as error:
                self._emit_error(str(error))
                self._set_status(STATUS_ERROR, str(error))
                self._close_connection()
            return

    def _connect_loop(self) -> None:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(20.0)
            client.connect((self.peer_host, self.tcp_port))
            client.settimeout(None)
            self._setup_connected_session(client)
        except ConnectionRefusedError:
            client.close()
            message = "Alice indisponível. Conexão recusada."
            self._emit_error(message)
            self._set_status(STATUS_ERROR, message)
        except OSError as error:
            client.close()
            message = f"Não foi possível conectar à Alice: {error}"
            self._emit_error(message)
            self._set_status(STATUS_ERROR, message)
        except (ProtocolError, RsaServiceError, ChatRuntimeError) as error:
            client.close()
            self._emit_error(str(error))
            self._set_status(STATUS_ERROR, str(error))

    def _setup_connected_session(self, connection: socket.socket) -> None:
        self._connection = connection
        self._exchange_public_keys()
        self._set_status(STATUS_CONNECTED)
        self._receiver = threading.Thread(
            target=self._receive_loop,
            daemon=True,
            name="tcp-receive",
        )
        self._receiver.start()

    def _exchange_public_keys(self) -> None:
        local_pem = read_public_pem_text(self.public_key_path)
        if self.role == ROLE_ALICE:
            self._send_packet(build_public_key_packet(self.local_user, local_pem))
            packet = self._receive_packet()
            self._store_remote_public_key(packet)
        else:
            packet = self._receive_packet()
            self._store_remote_public_key(packet)
            self._send_packet(build_public_key_packet(self.local_user, local_pem))

    def _store_remote_public_key(self, packet: dict[str, Any]) -> None:
        if packet.get("type") != PACKET_PUBLIC_KEY:
            raise ChatRuntimeError("A troca de chaves não recebeu um pacote public_key.")
        pem = packet["public_key"]
        public_key = load_public_key_from_pem(pem)
        validate_rsa_4096_public_key(public_key)
        self._remote_public_key = public_key
        self._remote_fingerprint = public_key_fingerprint(pem)
        self._emit(
            {
                "type": "peer_key",
                "peer_user": self.peer_user,
                "fingerprint": self._remote_fingerprint,
                "algorithm": "RSA-4096",
                "timestamp": self._now(),
            }
        )

    def _send_packet(self, data: dict[str, Any]) -> None:
        with self._socket_lock:
            if self._connection is None:
                raise ChatRuntimeError("Não há conexão TCP ativa.")
            send_packet(self._connection, data)

    def _receive_packet(self) -> dict[str, Any]:
        if self._connection is None:
            raise ChatRuntimeError("Não há conexão TCP ativa.")
        return receive_packet(self._connection)

    def _receive_loop(self) -> None:
        while not self._stop.is_set():
            try:
                packet = self._receive_packet()
            except ProtocolError as error:
                if self._stop.is_set():
                    return
                self._emit_error("A conexão TCP foi encerrada.")
                self._set_status(STATUS_DISCONNECTED, str(error))
                self._close_connection()
                return
            except OSError:
                if self._stop.is_set():
                    return
                self._emit_error("A conexão TCP foi encerrada.")
                self._set_status(STATUS_DISCONNECTED)
                self._close_connection()
                return

            try:
                self._handle_packet(packet)
            except (ProtocolError, RsaServiceError, ChatRuntimeError) as error:
                self._emit_error(str(error))

    def _handle_packet(self, packet: dict[str, Any]) -> None:
        packet_type = packet.get("type")
        if packet_type == PACKET_DISCONNECT:
            self._emit_error(f"{self.peer_user} encerrou a conexão.")
            self._set_status(STATUS_DISCONNECTED)
            self._close_connection()
            return
        if packet_type == PACKET_ENCRYPTED_MESSAGE:
            self._handle_encrypted_message(packet)
            return
        if packet_type == PACKET_MESSAGE_ACK:
            self._emit(
                {
                    "type": "message_ack",
                    "message_id": packet["message_id"],
                    "sender": packet["sender"],
                    "recipient": packet["recipient"],
                    "status": packet["status"],
                    "timestamp": self._now(),
                }
            )
            return
        if packet_type == PACKET_PUBLIC_KEY:
            self._store_remote_public_key(packet)

    def _handle_encrypted_message(self, packet: dict[str, Any]) -> None:
        message_id = packet.get("message_id") or str(uuid.uuid4())
        ciphertext_b64 = packet["ciphertext"]
        ciphertext = base64_to_encrypted_bytes(ciphertext_b64)
        plaintext = decrypt_message_with_private_key(ciphertext, self.private_key_path)

        event = self._message_event(
            message_id=message_id,
            direction="received",
            sender=packet.get("sender", self.peer_user),
            recipient=packet.get("recipient", self.local_user),
            plaintext=plaintext,
            ciphertext_b64=ciphertext_b64,
            ciphertext_size=len(ciphertext),
            delivery_status="decrypted",
        )
        self._emit(event)

        if packet.get("message_id"):
            ack = build_message_ack_packet(
                sender=self.local_user,
                recipient=self.peer_user,
                message_id=packet["message_id"],
                status="decrypted",
            )
            try:
                self._send_packet(ack)
            except (ProtocolError, ChatRuntimeError):
                pass

    def send_message(self, message: str) -> dict[str, Any]:
        if self._status != STATUS_CONNECTED:
            raise ChatRuntimeError("Ainda não há conexão TCP estabelecida.")
        if self._remote_public_key is None:
            raise ChatRuntimeError("A chave pública do outro participante ainda não foi recebida.")
        if not isinstance(message, str) or message.strip() == "":
            raise ChatRuntimeError("A mensagem não pode ser vazia.")

        plaintext = message
        ciphertext = encrypt_message_with_public_key_object(plaintext, self._remote_public_key)
        if len(ciphertext) != RSA_CIPHERTEXT_BYTES:
            raise ChatRuntimeError("O bloco RSA não teve 512 bytes.")

        ciphertext_b64 = encrypted_bytes_to_base64(ciphertext)
        message_id = str(uuid.uuid4())
        packet = build_encrypted_message_packet(
            sender=self.local_user,
            recipient=self.peer_user,
            ciphertext_base64=ciphertext_b64,
            message_id=message_id,
        )
        if "plaintext" in packet or "message" in packet:
            raise ChatRuntimeError("Bloqueado: o plaintext não pode entrar no pacote TCP.")

        self._send_packet(packet)
        event = self._message_event(
            message_id=message_id,
            direction="sent",
            sender=self.local_user,
            recipient=self.peer_user,
            plaintext=plaintext,
            ciphertext_b64=ciphertext_b64,
            ciphertext_size=len(ciphertext),
            delivery_status="sent_waiting",
        )
        self._emit(event)
        return event

    def _message_event(
        self,
        message_id: str,
        direction: str,
        sender: str,
        recipient: str,
        plaintext: str,
        ciphertext_b64: str,
        ciphertext_size: int,
        delivery_status: str,
    ) -> dict[str, Any]:
        encrypted_with = f"Chave pública de {self.peer_user if direction == 'sent' else self.local_user}"
        decrypted_with = None
        if direction == "received":
            decrypted_with = f"Chave privada local de {self.local_user}"

        return {
            "type": "message",
            "message_id": message_id,
            "direction": direction,
            "sender": sender,
            "recipient": recipient,
            "plaintext": plaintext,
            "plaintext_size": len(plaintext.encode("utf-8")),
            "ciphertext": ciphertext_b64,
            "ciphertext_size": ciphertext_size,
            "algorithm": "RSA-4096",
            "padding": "OAEP",
            "hash": "SHA-256",
            "encrypted_with": encrypted_with,
            "decrypted_with": decrypted_with,
            "original_in_tcp": False,
            "delivery_status": delivery_status,
            "timestamp": self._now(),
        }

    def disconnect(self) -> None:
        already_stopped = self._stop.is_set() and self._status == STATUS_DISCONNECTED
        self._stop.set()
        if self._connection is not None and not already_stopped:
            try:
                self._send_packet(build_disconnect_packet(self.local_user))
            except (ProtocolError, ChatRuntimeError, OSError):
                pass
        self._close_connection()
        self._close_server()
        if self._status != STATUS_DISCONNECTED:
            self._set_status(STATUS_DISCONNECTED)

    def _close_connection(self) -> None:
        with self._socket_lock:
            if self._connection is not None:
                try:
                    self._connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self._connection.close()
                except OSError:
                    pass
                self._connection = None
            self._remote_public_key = None
            self._remote_fingerprint = None

    def _close_server(self) -> None:
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None
