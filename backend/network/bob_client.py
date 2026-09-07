"""Cliente TCP do Bob.

Bob conecta-se ao servidor da Alice (--host/--port, padrão 127.0.0.1:5000).
Depois da troca de chaves públicas, cifra com a pública da Alice e
decifra com a privada local.

Por padrão usa backend/keys/ — no computador do Mussatto esse diretório
conterá o par gerado por ele. Para simular Bob no PC da Alice:

    python -m network.bob_client --keys-dir test_keys/bob

A chave privada nunca sai deste processo. TCP transporta bytes; o
cabeçalho de 4 bytes reconstitui o JSON porque recv() sozinho não
garante o pacote inteiro. Base64 só representa o ciphertext RSA.
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
SENDER_NAME = "Bob"
PEER_NAME = "Alice"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Cliente TCP do Bob. Usa as chaves locais em --keys-dir "
            "(padrão: backend/keys/)."
        )
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help="Endereço do servidor Alice.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Porta TCP do servidor Alice.",
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
    print("         BOB - CLIENTE TCP")
    print("========================================")
    print()
    print("Conectando ao servidor Alice...")
    print()
    print(f"Destino: {host}:{port}")
    print(f"Diretório de chaves locais: {keys_dir}")
    print()


def exchange_public_keys(connection: socket.socket, public_key_path: Path):
    """Recebe a pública da Alice, valida RSA-4096 e envia a pública local."""
    packet = receive_packet(connection)
    if packet.get("type") != PACKET_PUBLIC_KEY:
        raise ProtocolError(
            f"Esperava public_key da Alice, mas recebi: {packet.get('type')!r}"
        )

    alice_public_key = load_public_key_from_pem(packet["public_key"])
    validate_rsa_4096_public_key(alice_public_key)

    print("Chave pública da Alice recebida e validada.")
    print("Algoritmo: RSA")
    print(f"Tamanho: {alice_public_key.key_size} bits")
    print("Expoente público:", alice_public_key.public_numbers().e)
    print("A chave permanece somente em memória nesta conexão.")
    print()

    local_pem = read_public_pem_text(public_key_path)
    send_packet(connection, build_public_key_packet(SENDER_NAME, local_pem))
    print("Chave pública do Bob enviada à Alice.")
    print("A chave privada do Bob NÃO foi enviada.")
    print()
    return alice_public_key


def send_encrypted_message(connection: socket.socket, message: str, alice_public_key) -> None:
    """Cifra com a pública da Alice e envia só o ciphertext em Base64."""
    ciphertext = encrypt_message_with_public_key_object(message, alice_public_key)
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
    """Recebe um pacote da Alice e decifra com a privada local. None = disconnect."""
    packet = receive_packet(connection)
    packet_type = packet.get("type")

    if packet_type == PACKET_DISCONNECT:
        print()
        print(f"{packet.get('sender', PEER_NAME)} solicitou desconexão.")
        return None

    if packet_type != PACKET_ENCRYPTED_MESSAGE:
        raise ProtocolError(f"Pacote inesperado da Alice: {packet_type!r}")

    print()
    print("[RECEBIDO PELA REDE]")
    print(packet["ciphertext"])
    print()
    print("Campos recebidos no JSON:")
    print(", ".join(packet.keys()))
    print()
    print("Descriptografando com:")
    print("Chave privada local do Bob")
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


def _read_and_send_reply(
    connection: socket.socket,
    alice_public_key,
) -> bool:
    """Lê a resposta de Bob. Retorna False se a conversa deve encerrar."""
    while True:
        try:
            typed = input("Mensagem para Alice:\n")
        except EOFError:
            send_packet(connection, build_disconnect_packet(SENDER_NAME))
            print("Entrada encerrada. Desconexão enviada.")
            return False

        command = typed.strip()
        if command == "/sair":
            send_packet(connection, build_disconnect_packet(SENDER_NAME))
            print()
            print("Pedido de /sair enviado. Encerrando a conexão.")
            return False
        if command == "":
            print("A mensagem não pode ser vazia.")
            continue

        try:
            send_encrypted_message(connection, typed.rstrip("\r\n"), alice_public_key)
            return True
        except RsaServiceError as error:
            print()
            print(f"Não foi possível criptografar/enviar: {error}")
            print("Nenhum pacote foi enviado. Tente outra mensagem.")
            print()


def conversation_loop(
    connection: socket.socket,
    alice_public_key,
    private_key_path: Path,
) -> None:
    """Fluxo alternado: Bob recebe, responde, recebe, etc."""
    print("Conversa iniciada. Digite /sair para encerrar.")
    print()

    while True:
        try:
            received = receive_peer_packet(connection, private_key_path)
        except ProtocolError as error:
            print()
            print(f"A conexão foi encerrada: {error}")
            return

        if received is None:
            return

        if not _read_and_send_reply(connection, alice_public_key):
            return


def run_client(host: str, port: int, keys_dir: Path) -> int:
    _configure_stdio()
    _print_banner(host, port, keys_dir)

    public_key_path = keys_dir / "public_key.pem"
    private_key_path = keys_dir / "private_key.pem"

    if not public_key_path.exists() or not private_key_path.exists():
        print(f"As chaves locais não foram encontradas em: {keys_dir}")
        print("No computador real, gere o par com: python .\\crypto\\key_manager.py")
        print("Para simulação local no PC da Alice, gere antes:")
        print("    python .\\generate_bob_test_keys.py")
        print("e execute:")
        print("    python -m network.bob_client --keys-dir test_keys/bob")
        return 1

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
    except ConnectionRefusedError:
        print(
            "Conexão recusada. O servidor Alice (python -m network.alice_server) "
            "está em execução?"
        )
        client_socket.close()
        return 1
    except OSError as error:
        print(f"Não foi possível conectar ao servidor Alice em {host}:{port}: {error}")
        client_socket.close()
        return 1

    print("Conectado.")
    print(f"Servidor: {host}:{port}")
    print()

    try:
        alice_public_key = exchange_public_keys(client_socket, public_key_path)
        conversation_loop(client_socket, alice_public_key, private_key_path)
    except KeyboardInterrupt:
        print()
        print("Cliente interrompido pelo teclado.")
        try:
            send_packet(client_socket, build_disconnect_packet(SENDER_NAME))
        except ProtocolError:
            pass
    except ProtocolError as error:
        print()
        print(f"Erro de protocolo TCP: {error}")
        return 1
    except RsaServiceError as error:
        print()
        print(f"Erro criptográfico: {error}")
        return 1
    finally:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        client_socket.close()
        print()
        print("Cliente Bob encerrado.")

    return 0


def main() -> int:
    args = parse_args()
    keys_dir = resolve_keys_dir(args.keys_dir)
    return run_client(args.host, args.port, keys_dir)


if __name__ == "__main__":
    raise SystemExit(main())
