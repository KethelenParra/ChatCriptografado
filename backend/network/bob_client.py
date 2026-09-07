"""Cliente TCP do Bob para comunicação segura com criptografia RSA-4096.

Papel no Sistema:
    Bob atua como cliente TCP (lado ativo da conexão de transporte).
    Ele estabelece a conexão com o servidor da Alice (--host/--port, padrão 127.0.0.1:5000),
    participa do handshake inicial de chaves públicas e ingressa no laço de troca de mensagens.

Ciclo Criptográfico do Bob:
    1. Handshake Inicial:
       - Bob recebe a chave pública da Alice e a valida como RSA-4096, mantendo-a em memória.
       - Bob envia sua própria chave pública (public_key.pem) para a Alice.
       - A chave privada do Bob NUNCA é transmitida.
    2. Recepção de Mensagens (Alice -> Bob):
       - Bob recebe o pacote encrypted_message com o ciphertext em Base64.
       - Converte Base64 para bytes e descriptografa utilizando sua própria CHAVE PRIVADA LOCAL.
    3. Resposta Criptografada (Bob -> Alice):
       - Bob cifra o texto digitado utilizando a CHAVE PÚBLICA DA ALICE (RSA-OAEP/SHA-256).
       - O bloco cifrado de 512 bytes é codificado em Base64 e transmitido via TCP.
    4. Encerramento:
       - Trata o comando '/sair' enviando um pacote gracioso de desconexão.
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
    """Realiza a análise dos argumentos de linha de comando para o cliente Bob.

    Args:
        argv: Lista opcional de argumentos (se None, utiliza sys.argv).

    Returns:
        argparse.Namespace: Objeto contendo os argumentos processados (--host, --port, --keys-dir).
    """
    parser = argparse.ArgumentParser(
        description=(
            "Cliente TCP do Bob. Utiliza as chaves locais em --keys-dir "
            "(padrão: backend/keys/)."
        )
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help="Endereço do servidor Alice (ex.: 127.0.0.1 ou IP Tailscale da Alice).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Porta TCP do servidor Alice (padrão: 5000).",
    )
    parser.add_argument(
        "--keys-dir",
        default=DEFAULT_KEYS_DIR,
        help="Diretório das chaves locais do Bob, relativo a backend/ (padrão: keys).",
    )
    return parser.parse_args(argv)


def _configure_stdio() -> None:
    """Configura o encoding padrão de entrada e saída do terminal para UTF-8."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass


def _print_banner(host: str, port: int, keys_dir: Path) -> None:
    """Exibe o cabeçalho descritivo com parâmetros de conexão ao servidor Alice."""
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
    """Executa o handshake de troca de chaves públicas com a servidora Alice.

    Etapas do Handshake:
        1. Aguarda e recebe o pacote do tipo 'public_key' enviado por Alice.
        2. Valida se a chave recebida é estritamente RSA de 4096 bits.
        3. Carrega a chave pública local do Bob (public_key.pem) e envia para Alice.
        4. Mantém o objeto de chave pública da Alice em memória (não persiste em disco).

    Args:
        connection: Socket TCP conectado à Alice.
        public_key_path: Caminho para o arquivo public_key.pem local do Bob.

    Returns:
        RSAPublicKey: Chave pública da Alice validada e pronta para cifragem.

    Raises:
        ProtocolError: Se o pacote recebido for inválido ou não for do tipo public_key.
        RsaServiceError: Se a chave pública da Alice não possuir 4096 bits ou for inválida.
    """
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
    """Criptografa a mensagem com a chave pública da Alice e a envia via TCP.

    Garantia de Confidencialidade:
        O texto em claro é cifrado com RSA-4096 OAEP/SHA-256 localmente no Bob.
        Apenas o ciphertext codificado em Base64 é transmitido pela rede.

    Args:
        connection: Socket TCP conectado à Alice.
        message: Texto em claro digitado por Bob.
        alice_public_key: Instância de RSAPublicKey pertencente à Alice.

    Raises:
        RsaServiceError: Em caso de erro na cifragem ou violação de tamanho máximo.
        ProtocolError: Em caso de falha de transmissão TCP.
    """
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
    """Recebe um pacote TCP da Alice e decifra o ciphertext com a chave privada do Bob.

    Args:
        connection: Socket TCP ativo com a Alice.
        private_key_path: Caminho até a chave privada local do Bob.

    Returns:
        str: Mensagem em claro descriptografada, ou None se Alice solicitou desconexão.

    Raises:
        ProtocolError: Se o pacote for inválido ou não for encrypted_message/disconnect.
        RsaServiceError: Se a descriptografia RSA com a chave privada falhar.
    """
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
    """Lê a entrada do usuário Bob pelo teclado e envia a resposta criptografada.

    Args:
        connection: Socket TCP conectado.
        alice_public_key: Chave pública de Alice.

    Returns:
        bool: True se a mensagem foi enviada com sucesso; False se a sessão foi encerrada (/sair).
    """
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
    """Executa o laço de conversa no terminal do Bob (aguarda Alice enviar -> Bob responde).

    Args:
        connection: Socket TCP conectado à Alice.
        alice_public_key: Chave pública da Alice.
        private_key_path: Caminho da chave privada local do Bob.
    """
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
    """Conecta o cliente Bob ao servidor da Alice, gerencia a sessão e finaliza recursos.

    Args:
        host: Endereço IP ou hostname do servidor Alice.
        port: Porta TCP.
        keys_dir: Diretório das chaves locais do Bob.

    Returns:
        int: Código de status do processo (0 para sucesso, 1 para erro).
    """
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
    """Ponto de entrada do script para execução do cliente Bob."""
    args = parse_args()
    keys_dir = resolve_keys_dir(args.keys_dir)
    return run_client(args.host, args.port, keys_dir)


if __name__ == "__main__":
    raise SystemExit(main())

