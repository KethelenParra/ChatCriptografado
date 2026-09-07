"""Simulação de comunicação criptográfica assimétrica bidirecional entre Alice e Bob.

Finalidade Acadêmica:
    Validar em ambiente controlado a troca segura de mensagens entre dois participantes
    distintos com seus respectivos pares de chaves RSA-4096:
    
        Participante 1 (Alice):
            - Chave pública: backend/keys/public_key.pem
            - Chave privada: backend/keys/private_key.pem
            
        Participante 2 (Bob simulado):
            - Chave pública: backend/test_keys/bob/public_key.pem
            - Chave privada: backend/test_keys/bob/private_key.pem

Roteiro de Validação Criptográfica:
    1. Fluxo Alice -> Bob:
       Alice cifra com a chave pública do Bob; Bob descriptografa com sua chave privada.
    2. Fluxo Bob -> Alice:
       Bob cifra com a chave pública da Alice; Alice descriptografa com sua chave privada.
    3. Teste Negativo de Confidencialidade (Chave Incorreta):
       Alice tenta abrir uma mensagem cifrada para o Bob utilizando sua própria chave privada.
       A operação DEVE falhar obrigatoriamente, comprovando que apenas o detentor da chave
       privada correspondente à chave pública usada na cifragem consegue decifrar o conteúdo.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

from crypto.key_manager import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH
from crypto.rsa_service import (
    RSA_CIPHERTEXT_BYTES,
    RsaServiceError,
    decrypt_message_with_private_key,
    encrypt_message_with_public_key,
    encrypted_bytes_to_base64,
)

BACKEND_DIR = Path(__file__).resolve().parent
BOB_PRIVATE_KEY_PATH = BACKEND_DIR / "test_keys" / "bob" / "private_key.pem"
BOB_PUBLIC_KEY_PATH = BACKEND_DIR / "test_keys" / "bob" / "public_key.pem"

ALICE_TO_BOB_MESSAGE = (
    "Olá Bob! Aqui é Alice. Esta mensagem foi criptografada para você."
)
BOB_TO_ALICE_MESSAGE = (
    "Olá Alice! Aqui é Bob. Recebi sua mensagem com segurança."
)

# Exceções esperadas da biblioteca cryptography quando a chave privada é inadequada
EXPECTED_DECRYPT_FAILURES = (ValueError, InvalidTag)


def _configure_stdout() -> None:
    """Garante acentuação correta no terminal do Windows."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass


def test_alice_to_bob() -> bytes:
    """Simula o envio de mensagem de Alice para Bob (cifra com pública do Bob, decifra com privada do Bob).

    Returns:
        bytes: Bloco criptografado gerado no teste (512 bytes).

    Raises:
        RsaServiceError: Se a mensagem recuperada não for idêntica à original.
    """
    print("========================================")
    print("          ALICE -> BOB")
    print("========================================")
    print()
    print("Remetente:")
    print("Alice")
    print()
    print("Destinatário:")
    print("Bob")
    print()
    print("[MENSAGEM ORIGINAL]")
    print()
    print(ALICE_TO_BOB_MESSAGE)
    print()
    print("Criptografando com:")
    print("CHAVE PÚBLICA DO BOB")
    print()

    ciphertext = encrypt_message_with_public_key(
        ALICE_TO_BOB_MESSAGE,
        BOB_PUBLIC_KEY_PATH,
    )

    print("[MENSAGEM CRIPTOGRAFADA - BASE64]")
    print()
    print(encrypted_bytes_to_base64(ciphertext))
    print()
    print("Tamanho criptografado:")
    print(f"{len(ciphertext)} bytes")
    print()
    print("Bob recebeu:")
    print("DADOS CRIPTOGRAFADOS")
    print()
    print("Descriptografando com:")
    print("CHAVE PRIVADA DO BOB")
    print()

    recovered = decrypt_message_with_private_key(ciphertext, BOB_PRIVATE_KEY_PATH)

    print("[MENSAGEM DESCRIPTOGRAFADA]")
    print()
    print(recovered)
    print()

    messages_match = recovered == ALICE_TO_BOB_MESSAGE
    size_ok = len(ciphertext) == RSA_CIPHERTEXT_BYTES

    print("Mensagem recuperada = original:")
    print("SIM" if messages_match else "NÃO")
    print()
    print("Status:")
    if messages_match and size_ok:
        print("ALICE -> BOB OK")
    else:
        print("ALICE -> BOB FALHOU")
        raise RsaServiceError("O teste Alice -> Bob não recuperou a mensagem original.")
    print()
    return ciphertext


def test_bob_to_alice() -> bytes:
    """Simula o envio de mensagem de Bob para Alice (cifra com pública de Alice, decifra com privada de Alice).

    Returns:
        bytes: Bloco criptografado gerado no teste (512 bytes).

    Raises:
        RsaServiceError: Se a mensagem recuperada não for idêntica à original.
    """
    print("========================================")
    print("          BOB -> ALICE")
    print("========================================")
    print()
    print("Remetente:")
    print("Bob")
    print()
    print("Destinatário:")
    print("Alice")
    print()
    print("[MENSAGEM ORIGINAL]")
    print()
    print(BOB_TO_ALICE_MESSAGE)
    print()
    print("Criptografando com:")
    print("CHAVE PÚBLICA DA ALICE")
    print()

    ciphertext = encrypt_message_with_public_key(
        BOB_TO_ALICE_MESSAGE,
        PUBLIC_KEY_PATH,
    )

    print("[MENSAGEM CRIPTOGRAFADA - BASE64]")
    print()
    print(encrypted_bytes_to_base64(ciphertext))
    print()
    print("Tamanho:")
    print(f"{len(ciphertext)} bytes")
    print()
    print("Alice recebeu:")
    print("DADOS CRIPTOGRAFADOS")
    print()
    print("Descriptografando com:")
    print("CHAVE PRIVADA DA ALICE")
    print()

    recovered = decrypt_message_with_private_key(ciphertext, PRIVATE_KEY_PATH)

    print("[MENSAGEM DESCRIPTOGRAFADA]")
    print()
    print(recovered)
    print()

    messages_match = recovered == BOB_TO_ALICE_MESSAGE
    size_ok = len(ciphertext) == RSA_CIPHERTEXT_BYTES

    print("Mensagem recuperada = original:")
    print("SIM" if messages_match else "NÃO")
    print()
    print("Status:")
    if messages_match and size_ok:
        print("BOB -> ALICE OK")
    else:
        print("BOB -> ALICE FALHOU")
        raise RsaServiceError("O teste Bob -> Alice não recuperou a mensagem original.")
    print()
    return ciphertext


def test_wrong_private_key(alice_to_bob_ciphertext: bytes) -> None:
    """Valida o princípio de confidencialidade assimétrica tentando decifrar com a chave privada incorreta.

    Tenta abrir a mensagem destinada a Bob utilizando a chave privada da Alice.
    A falha de desempacotamento do padding OAEP é a consequência matemática esperada.

    Args:
        alice_to_bob_ciphertext: Bloco cifrado com a chave pública de Bob.

    Raises:
        RsaServiceError: Se a descriptografia indevidamente tiver sucesso.
    """
    print("========================================")
    print("       TESTE DE CHAVE INCORRETA")
    print("========================================")
    print()
    print("Mensagem destinada:")
    print("Bob")
    print()
    print("Criptografada com:")
    print("Chave pública do Bob")
    print()
    print("Tentativa de abertura com:")
    print("Chave privada da Alice")
    print()

    try:
        decrypt_message_with_private_key(
            alice_to_bob_ciphertext,
            PRIVATE_KEY_PATH,
        )
    except EXPECTED_DECRYPT_FAILURES:
        failed_as_expected = True
    except RsaServiceError as error:
        if isinstance(error.__cause__, EXPECTED_DECRYPT_FAILURES):
            failed_as_expected = True
        else:
            raise
    else:
        failed_as_expected = False

    if not failed_as_expected:
        print("Resultado:")
        print("INESPERADO: a descriptografia com a chave errada funcionou.")
        print()
        print("Status:")
        print("PROTEÇÃO ASSIMÉTRICA NÃO CONFIRMADA")
        raise RsaServiceError(
            "A mensagem cifrada para Bob não deveria abrir com a privada da Alice."
        )

    print("Resultado:")
    print("FALHA, COMO ESPERADO")
    print()
    print("Motivo:")
    print("A chave privada da Alice não corresponde à chave pública do Bob.")
    print()
    print("Status:")
    print("PROTEÇÃO ASSIMÉTRICA CONFIRMADA")
    print()


def print_final_summary() -> None:
    """Exibe o sumário consolidado da suíte de testes de simulação criptográfica."""
    print("========================================")
    print("          RESULTADO FINAL")
    print("========================================")
    print()
    print("RSA:")
    print("4096 bits")
    print()
    print("Padding:")
    print("OAEP")
    print()
    print("Hash:")
    print("SHA-256")
    print()
    print("Alice -> Bob:")
    print("OK")
    print()
    print("Bob -> Alice:")
    print("OK")
    print()
    print("Chave privada incorreta:")
    print("FALHOU COMO ESPERADO")
    print()
    print("Resultado geral:")
    print("COMUNICAÇÃO CRIPTOGRÁFICA ENTRE ALICE E BOB VALIDADA")
    print()
    print("========================================")


def main() -> None:
    """Ponto de entrada do script para execução da simulação Alice ↔ Bob."""
    _configure_stdout()
    try:
        alice_to_bob_ciphertext = test_alice_to_bob()
        test_bob_to_alice()
        test_wrong_private_key(alice_to_bob_ciphertext)
        print_final_summary()
    except RsaServiceError as error:
        print()
        print(f"Erro: {error}")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()

