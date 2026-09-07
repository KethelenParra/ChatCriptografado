"""Servidor TCP da Alice.

O servidor escuta em um host/porta configuráveis (padrão 127.0.0.1:5000),
aceita o cliente Bob e troca somente chaves públicas. As mensagens são
cifradas com RSA-4096 + OAEP/SHA-256 usando a chave pública recebida
do destinatário.

A chave privada permanece neste computador, em --keys-dir (padrão:
backend/keys/). Nunca é impressa nem enviada pelo TCP.

TCP Socket cria um canal de bytes confiável. recv() pode devolver só
um pedaço; o framing de 4 bytes reconstitui o JSON. A mensagem original
nunca entra no pacote: só o ciphertext em Base64 (Base64 não é cifra).
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

from crypto.rsa_service import (
    RSA_CIPHERTEXT_BYTES,
    RsaServiceError,
    base64_to_encrypted_bytes,
    decrypt_message_with_private_key,
    encrypt_message_with_public_key_object,
    encrypted_bytes_to_base64,
    load_public_key_from_pem,
    read_public_pem_text,
    validate_rsa_4096_public_key,
)
from network import resolve_keys_dir
from network.protocol import (
    PACKET_DISCONNECT,
    PACKET_ENCRYPTED_MESSAGE,
    PACKET_PUBLIC_KEY,
    ProtocolError,
    build_disconnect_packet,
    build_encrypted_message_packet,
    build_public_key_packet,
    receive_packet,
    send_packet,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
DEFAULT_KEYS_DIR = "keys"
SENDER_NAME = "Alice"
PEER_NAME = "Bob"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Servidor TCP da Alice. Usa as chaves locais em --keys-dir "
            "(padrão: backend/keys/)."
        )
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help="Endereço de escuta. Use 0.0.0.0 para aceitar conexões da rede.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Porta TCP de escuta.",
    )
    parser.add_argument(
        "--keys-dir",
        default=DEFAULT_KEYS_DIR,
        help="Diretório das chaves locais, relativo a backend/.",
    )
    return parser.parse_args(argv)


def _configure_stdio() -> None:
    """Garante acentuação correta no terminal do Windows."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass


def _print_banner(host: str, port: int, keys_dir: Path) -> None:
    print("========================================")
    print("       ALICE - SERVIDOR TCP")
    print("========================================")
    print()
    print("Servidor aguardando conexão...")
    print()
    print("IP:")
    print(host)
    print()
    print("Porta:")
    print(port)
    print()
    print("Diretório de chaves locais:")
    print(keys_dir)
    print()


def exchange_public_keys(connection: socket.socket, public_key_path: Path):
    """Envia a pública local e recebe a pública do Bob só em memória."""
    local_pem = read_public_pem_text(public_key_path)
    send_packet(connection, build_public_key_packet(SENDER_NAME, local_pem))
    print("Chave pública da Alice enviada ao Bob.")
    print("A chave privada da Alice NÃO foi enviada.")
    print()

    packet = receive_packet(connection)
    if packet.get("type") != PACKET_PUBLIC_KEY:
        raise ProtocolError(
            f"Esperava public_key do Bob, mas recebi: {packet.get('type')!r}"
        )

    bob_public_key = load_public_key_from_pem(packet["public_key"])
    validate_rsa_4096_public_key(bob_public_key)

    print("Chave pública do Bob recebida e validada.")
    print("Algoritmo: RSA")
    print(f"Tamanho: {bob_public_key.key_size} bits")
    print("Expoente público:", bob_public_key.public_numbers().e)
    print("A chave permanece somente em memória nesta conexão.")
    print()
    return bob_public_key


def send_encrypted_message(connection: socket.socket, message: str, bob_public_key) -> None:
    """Cifra com a pública do Bob e envia só o ciphertext em Base64."""
    ciphertext = encrypt_message_with_public_key_object(message, bob_public_key)
    ciphertext_b64 = encrypted_bytes_to_base64(ciphertext)
    packet = build_encrypted_message_packet(SENDER_NAME, PEER_NAME, ciphertext_b64)

    print()
    print("[ORIGINAL]")
    print(message)
    print()
    print("[CRIPTOGRAFADA]")
    print(ciphertext_b64)
    print()
    print("Tamanho do ciphertext:")
    print(f"{len(ciphertext)} bytes")
    if len(ciphertext) != RSA_CIPHERTEXT_BYTES:
        print("Aviso: o bloco RSA não teve 512 bytes.")
    print()
    print("Campos enviados no JSON:")
    print(", ".join(packet.keys()))
    print("A mensagem original NÃO está no pacote TCP.")
    print()
    print("Enviando via TCP...")
    send_packet(connection, packet)
    print("Pacote enviado.")
    print()


def receive_peer_packet(connection: socket.socket, private_key_path: Path) -> str | None:
    """Recebe um pacote do Bob e decifra com a privada local. None = disconnect."""
    packet = receive_packet(connection)
    packet_type = packet.get("type")

    if packet_type == PACKET_DISCONNECT:
        print()
        print(f"{packet.get('sender', PEER_NAME)} solicitou desconexão.")
        return None

    if packet_type != PACKET_ENCRYPTED_MESSAGE:
        raise ProtocolError(f"Pacote inesperado do Bob: {packet_type!r}")

    print()
    print("[RECEBIDO PELA REDE]")
    print(packet["ciphertext"])
    print()
    print("Campos recebidos no JSON:")
    print(", ".join(packet.keys()))
    print()
    print("Descriptografando com:")
    print("Chave privada local da Alice")
    print()

    ciphertext = base64_to_encrypted_bytes(packet["ciphertext"])
    print("Tamanho do ciphertext:")
    print(f"{len(ciphertext)} bytes")
    print()

    plaintext = decrypt_message_with_private_key(ciphertext, private_key_path)
    print("[MENSAGEM]")
    print(plaintext)
    print()
    return plaintext


def conversation_loop(
    connection: socket.socket,
    bob_public_key,
    private_key_path: Path,
) -> None:
    """Fluxo alternado: Alice envia, Bob responde, Alice envia, etc."""
    print("Conversa iniciada. Digite /sair para encerrar.")
    print()

    while True:
        try:
            typed = input("Mensagem para Bob:\n")
        except EOFError:
            send_packet(connection, build_disconnect_packet(SENDER_NAME))
            print("Entrada encerrada. Desconexão enviada.")
            return

        command = typed.strip()
        if command == "/sair":
            send_packet(connection, build_disconnect_packet(SENDER_NAME))
            print()
            print("Pedido de /sair enviado. Encerrando a conexão.")
            return
        if command == "":
            print("A mensagem não pode ser vazia.")
            continue

        try:
            send_encrypted_message(connection, typed.rstrip("\r\n"), bob_public_key)
        except RsaServiceError as error:
            print()
            print(f"Não foi possível criptografar/enviar: {error}")
            print("Nenhum pacote foi enviado. Tente outra mensagem.")
            print()
            continue

        try:
            received = receive_peer_packet(connection, private_key_path)
        except ProtocolError as error:
            print()
            print(f"A conexão foi encerrada: {error}")
            return

        if received is None:
            return


def run_server(host: str, port: int, keys_dir: Path) -> int:
    _configure_stdio()

    public_key_path = keys_dir / "public_key.pem"
    private_key_path = keys_dir / "private_key.pem"

    if not public_key_path.exists() or not private_key_path.exists():
        print(f"As chaves locais não foram encontradas em: {keys_dir}")
        print("Gere o par neste computador com: python .\\crypto\\key_manager.py")
        return 1

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(1)
    except OSError as error:
        print(f"Não foi possível iniciar o servidor Alice em {host}:{port}: {error}")
        server_socket.close()
        return 1

    _print_banner(host, port, keys_dir)

    connection = None
    try:
        connection, address = server_socket.accept()
        print("Bob conectado.")
        print(f"Endereço: {address[0]}:{address[1]}")
        print()

        bob_public_key = exchange_public_keys(connection, public_key_path)
        conversation_loop(connection, bob_public_key, private_key_path)
    except KeyboardInterrupt:
        print()
        print("Servidor interrompido pelo teclado.")
    except ProtocolError as error:
        print()
        print(f"Erro de protocolo TCP: {error}")
        return 1
    except RsaServiceError as error:
        print()
        print(f"Erro criptográfico: {error}")
        return 1
    finally:
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        server_socket.close()
        print()
        print("Servidor Alice encerrado.")

    return 0


def main() -> int:
    args = parse_args()
    keys_dir = resolve_keys_dir(args.keys_dir)
    return run_server(args.host, args.port, keys_dir)


if __name__ == "__main__":
    raise SystemExit(main())
