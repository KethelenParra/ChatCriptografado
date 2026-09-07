"""Teste didático da criptografia RSA-4096 com OAEP e SHA-256.

Demonstra o fluxo local desta etapa:

    mensagem original
        → chave pública da Alice
        → RSA-4096 + OAEP + SHA-256
        → mensagem criptografada
        → chave privada da Alice
        → mensagem descriptografada

Não há comunicação de rede. As chaves já existentes não são geradas
novamente. O conteúdo da chave privada nunca é impresso.
"""

from __future__ import annotations

import sys

from crypto.rsa_service import (
    RSA_CIPHERTEXT_BYTES,
    RsaServiceError,
    decrypt_message,
    encrypt_message,
    encrypted_bytes_to_base64,
)


TEST_MESSAGE = "Olá Alice! Esta mensagem está protegida com RSA-4096."


def _configure_stdout() -> None:
    """Garante acentuação correta no terminal do Windows."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass


def run_test() -> str:
    """Executa o teste didático e devolve o Base64 do ciphertext."""
    original_message = TEST_MESSAGE
    original_size = len(original_message.encode("utf-8"))

    print("========================================")
    print("       TESTE DE CRIPTOGRAFIA RSA")
    print("========================================")
    print()
    print("Algoritmo: RSA-4096")
    print("Padding: OAEP")
    print("Hash: SHA-256")
    print()
    print("[MENSAGEM ORIGINAL]")
    print()
    print(original_message)
    print()
    print("Tamanho original:")
    print(f"{original_size} bytes")
    print()
    print("----------------------------------------")
    print()
    print("CRIPTOGRAFANDO...")
    print()
    print("Utilizando:")
    print("Chave pública da Alice")
    print()

    encrypted_bytes = encrypt_message(original_message)
    encrypted_base64 = encrypted_bytes_to_base64(encrypted_bytes)

    print("[MENSAGEM CRIPTOGRAFADA - BASE64]")
    print()
    print(encrypted_base64)
    print()
    print("Tamanho criptografado:")
    print(f"{len(encrypted_bytes)} bytes")
    print()
    print("----------------------------------------")
    print()
    print("DESCRIPTOGRAFANDO...")
    print()
    print("Utilizando:")
    print("Chave privada da Alice")
    print()

    decrypted_message = decrypt_message(encrypted_bytes)

    print("[MENSAGEM DESCRIPTOGRAFADA]")
    print()
    print(decrypted_message)
    print()
    print("----------------------------------------")
    print()

    messages_match = original_message == decrypted_message
    ciphertext_size_ok = len(encrypted_bytes) == RSA_CIPHERTEXT_BYTES
    ciphertext_differs = encrypted_bytes != original_message.encode("utf-8")

    print(
        "Mensagem original = mensagem recuperada: "
        f"{'SIM' if messages_match else 'NÃO'}"
    )
    print()

    if messages_match and ciphertext_size_ok and ciphertext_differs:
        print("Status:")
        print("CRIPTOGRAFIA E DESCRIPTOGRAFIA RSA-4096 FUNCIONANDO")
        print()
        print("Integridade do teste: OK")
    else:
        print("Status:")
        print("FALHA NO TESTE RSA")
        if not ciphertext_differs:
            print("A mensagem criptografada não deveria coincidir com a original.")
        if not ciphertext_size_ok:
            print(
                f"O bloco cifrado deveria ter {RSA_CIPHERTEXT_BYTES} bytes, "
                f"mas teve {len(encrypted_bytes)}."
            )
        if not messages_match:
            print("A mensagem recuperada é diferente da original.")

    print()
    print("========================================")
    return encrypted_base64


def main() -> None:
    _configure_stdout()
    try:
        run_test()
    except RsaServiceError as error:
        print()
        print(f"Erro: {error}")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
