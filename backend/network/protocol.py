"""Protocolo de enquadramento sobre TCP Socket.

TCP é um fluxo contínuo de bytes: um único recv() pode devolver só
parte da mensagem, ou juntar várias. Por isso cada pacote começa com
um cabeçalho de 4 bytes (tamanho em big-endian) seguido do JSON UTF-8.

Formato:

    [4 bytes com o tamanho][payload JSON]

Somente a chave pública pode ser compartilhada. A chave privada nunca
entra no JSON. Em mensagens, o TCP transporta só o ciphertext em Base64;
Base64 não é criptografia, apenas representação textual dos bytes RSA.
"""

from __future__ import annotations

import json
import socket

HEADER_SIZE = 4
MAX_PAYLOAD_BYTES = 1_000_000

PACKET_PUBLIC_KEY = "public_key"
PACKET_ENCRYPTED_MESSAGE = "encrypted_message"
PACKET_DISCONNECT = "disconnect"
PACKET_MESSAGE_ACK = "message_ack"

# Campos obrigatórios do ciphertext. message_id é opcional para
# compatibilidade com os scripts de terminal, e obrigatório no runtime GUI.
ENCRYPTED_MESSAGE_REQUIRED_FIELDS = ("type", "sender", "recipient", "ciphertext")
ENCRYPTED_MESSAGE_ALLOWED_FIELDS = ENCRYPTED_MESSAGE_REQUIRED_FIELDS + ("message_id",)
MESSAGE_ACK_FIELDS = ("type", "message_id", "sender", "recipient", "status")
FORBIDDEN_PLAINTEXT_FIELDS = (
    "message",
    "plaintext",
    "original",
    "texto",
    "private_key",
)


class ProtocolError(Exception):
    """Erro no enquadramento, no JSON ou no conteúdo do pacote TCP."""


def recv_exact(connection: socket.socket, number_of_bytes: int) -> bytes:
    """Lê exatamente number_of_bytes do socket, possivelmente em vários recv().

    recv() sozinho não garante a mensagem inteira. Esta função junta os
    pedaços até completar o tamanho pedido. Se o peer fechar a conexão
    no meio do pacote, a leitura é interrompida com erro claro.
    """
    if number_of_bytes < 0:
        raise ProtocolError("O número de bytes solicitado é inválido.")

    chunks = bytearray()
    while len(chunks) < number_of_bytes:
        remaining = number_of_bytes - len(chunks)
        try:
            piece = connection.recv(remaining)
        except ConnectionResetError as error:
            raise ProtocolError(
                "A conexão foi encerrada pelo outro lado durante a leitura."
            ) from error
        except OSError as error:
            raise ProtocolError(
                f"Falha de leitura no socket TCP: {error}"
            ) from error

        if piece == b"":
            if len(chunks) == 0:
                raise ProtocolError("A conexão TCP foi encerrada.")
            raise ProtocolError(
                "A conexão foi encerrada antes de receber o pacote completo."
            )
        chunks.extend(piece)

    return bytes(chunks)


def send_packet(connection: socket.socket, data: dict) -> None:
    """Serializa um dicionário em JSON UTF-8 e envia com cabeçalho de 4 bytes."""
    if not isinstance(data, dict):
        raise ProtocolError("O pacote precisa ser um dicionário JSON.")

    _validate_outgoing_packet(data)

    try:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as error:
        raise ProtocolError(f"Não foi possível converter o pacote para JSON: {error}") from error

    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("O pacote JSON excede o tamanho máximo permitido.")

    header = len(payload).to_bytes(HEADER_SIZE, byteorder="big")
    try:
        connection.sendall(header + payload)
    except BrokenPipeError as error:
        raise ProtocolError("Não foi possível enviar: o outro lado encerrou a conexão.") from error
    except ConnectionResetError as error:
        raise ProtocolError("A conexão foi reiniciada durante o envio.") from error
    except OSError as error:
        raise ProtocolError(f"Falha de envio no socket TCP: {error}") from error


def receive_packet(connection: socket.socket) -> dict:
    """Recebe o cabeçalho de 4 bytes e, em seguida, o JSON completo."""
    header = recv_exact(connection, HEADER_SIZE)
    payload_size = int.from_bytes(header, byteorder="big")

    if payload_size == 0:
        raise ProtocolError("O cabeçalho TCP indicou um payload vazio.")
    if payload_size > MAX_PAYLOAD_BYTES:
        raise ProtocolError(
            f"O cabeçalho TCP indicou {payload_size} bytes, acima do limite permitido."
        )

    payload = recv_exact(connection, payload_size)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError(
            f"O payload TCP não está em UTF-8 válido: {error}"
        ) from error

    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ProtocolError(f"O payload TCP não é um JSON válido: {error}") from error

    if not isinstance(data, dict):
        raise ProtocolError("O JSON recebido precisa ser um objeto (dicionário).")

    _validate_incoming_packet(data)
    return data


def build_public_key_packet(sender: str, public_key_pem: str) -> dict:
    """Monta o pacote de troca de chave pública. A privada nunca entra aqui."""
    return {
        "type": PACKET_PUBLIC_KEY,
        "sender": sender,
        "public_key": public_key_pem,
    }


def build_encrypted_message_packet(
    sender: str,
    recipient: str,
    ciphertext_base64: str,
    message_id: str | None = None,
) -> dict:
    """Monta o pacote de mensagem. Só metadados e o ciphertext em Base64.

    O texto original nunca entra neste dicionário. message_id é metadado
    para o ACK de descriptografia da interface gráfica.
    """
    packet = {
        "type": PACKET_ENCRYPTED_MESSAGE,
        "sender": sender,
        "recipient": recipient,
        "ciphertext": ciphertext_base64,
    }
    if message_id:
        packet["message_id"] = message_id
    return packet


def build_message_ack_packet(
    sender: str,
    recipient: str,
    message_id: str,
    status: str = "decrypted",
) -> dict:
    """Confirma que o destinatário descriptografou a mensagem com sucesso."""
    return {
        "type": PACKET_MESSAGE_ACK,
        "message_id": message_id,
        "sender": sender,
        "recipient": recipient,
        "status": status,
    }


def build_disconnect_packet(sender: str) -> dict:
    """Monta o aviso de encerramento da conversa."""
    return {
        "type": PACKET_DISCONNECT,
        "sender": sender,
    }


def _validate_outgoing_packet(data: dict) -> None:
    packet_type = data.get("type")
    if packet_type == PACKET_ENCRYPTED_MESSAGE:
        _assert_encrypted_message_shape(data)
    elif packet_type == PACKET_PUBLIC_KEY:
        if "PRIVATE KEY" in str(data.get("public_key", "")):
            raise ProtocolError(
                "Bloqueado: uma chave privada não pode ser enviada pela rede."
            )
    elif packet_type == PACKET_DISCONNECT:
        return
    elif packet_type == PACKET_MESSAGE_ACK:
        _assert_message_ack_shape(data)
    else:
        raise ProtocolError(f"Tipo de pacote de saída desconhecido: {packet_type!r}")


def _validate_incoming_packet(data: dict) -> None:
    packet_type = data.get("type")
    if packet_type not in {
        PACKET_PUBLIC_KEY,
        PACKET_ENCRYPTED_MESSAGE,
        PACKET_DISCONNECT,
        PACKET_MESSAGE_ACK,
    }:
        raise ProtocolError(f"Tipo de pacote recebido desconhecido: {packet_type!r}")

    for forbidden in FORBIDDEN_PLAINTEXT_FIELDS:
        if forbidden in data:
            raise ProtocolError(
                f"O pacote TCP contém o campo proibido '{forbidden}'. "
                "A mensagem original não pode trafegar pela rede."
            )

    if packet_type == PACKET_ENCRYPTED_MESSAGE:
        _assert_encrypted_message_shape(data)
    elif packet_type == PACKET_MESSAGE_ACK:
        _assert_message_ack_shape(data)
    elif packet_type == PACKET_PUBLIC_KEY:
        pem = data.get("public_key")
        if not isinstance(pem, str) or pem.strip() == "":
            raise ProtocolError("O pacote public_key não trouxe uma chave pública.")
        if "PRIVATE KEY" in pem:
            raise ProtocolError(
                "Bloqueado: o peer tentou enviar uma chave privada."
            )


def _assert_encrypted_message_shape(data: dict) -> None:
    extra = set(data.keys()) - set(ENCRYPTED_MESSAGE_ALLOWED_FIELDS)
    missing = set(ENCRYPTED_MESSAGE_REQUIRED_FIELDS) - set(data.keys())
    if missing:
        raise ProtocolError(
            "Pacote encrypted_message incompleto. "
            f"Campos ausentes: {', '.join(sorted(missing))}."
        )
    if extra:
        raise ProtocolError(
            "Pacote encrypted_message contém campos extras. "
            "Permitidos: type, sender, recipient, ciphertext e message_id. "
            f"Campos extras: {', '.join(sorted(extra))}."
        )
    if not isinstance(data["ciphertext"], str) or data["ciphertext"].strip() == "":
        raise ProtocolError("O campo ciphertext precisa ser uma string Base64.")
    message_id = data.get("message_id")
    if message_id is not None and (not isinstance(message_id, str) or not message_id.strip()):
        raise ProtocolError("O campo message_id precisa ser um texto não vazio.")


def _assert_message_ack_shape(data: dict) -> None:
    extra = set(data.keys()) - set(MESSAGE_ACK_FIELDS)
    missing = set(MESSAGE_ACK_FIELDS) - set(data.keys())
    if missing:
        raise ProtocolError(
            "Pacote message_ack incompleto. "
            f"Campos ausentes: {', '.join(sorted(missing))}."
        )
    if extra:
        raise ProtocolError(
            "Pacote message_ack contém campos extras. "
            f"Campos extras: {', '.join(sorted(extra))}."
        )
    if data.get("status") != "decrypted":
        raise ProtocolError("O ACK só pode confirmar status 'decrypted'.")
    if not isinstance(data.get("message_id"), str) or not data["message_id"].strip():
        raise ProtocolError("O ACK precisa identificar a mensagem.")
