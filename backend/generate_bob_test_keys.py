"""Gera um par RSA-4096 de TESTE para simular o Bob neste computador.

Essas chaves NÃO pertencem ao Gabriel Mussatto. Quando ele entrar no
projeto, gerará o próprio par no computador dele.

As chaves da Alice em backend/keys/ NÃO são lidas, movidas nem
substituídas por este script.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto.key_manager import RSA_KEY_SIZE, RSA_PUBLIC_EXPONENT

BACKEND_DIR = Path(__file__).resolve().parent

# Pasta exclusiva das chaves de teste do Bob. Não confundir com
# backend/keys/, que contém o par real da Alice neste projeto.
BOB_TEST_KEYS_DIR = BACKEND_DIR / "test_keys" / "bob"
BOB_PRIVATE_KEY_PATH = BOB_TEST_KEYS_DIR / "private_key.pem"
BOB_PUBLIC_KEY_PATH = BOB_TEST_KEYS_DIR / "public_key.pem"


class BobTestKeyError(Exception):
    """Erro na geração ou verificação das chaves de teste do Bob."""


def _configure_stdout() -> None:
    """Garante acentuação correta no terminal do Windows."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass


def bob_test_keys_exist() -> bool:
    """Retorna True se qualquer arquivo PEM de teste do Bob já existir."""
    return BOB_PRIVATE_KEY_PATH.exists() or BOB_PUBLIC_KEY_PATH.exists()


def generate_bob_test_keys() -> bool:
    """Gera o par RSA-4096 de teste do Bob, sem sobrescrever arquivos.

    Retorna True se um novo par foi gerado e False se as chaves já existiam.
    """
    BOB_TEST_KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if bob_test_keys_exist():
        print("As chaves RSA de teste do Bob já existem.")
        print(f"Chave privada (não será exibida): {BOB_PRIVATE_KEY_PATH}")
        print(f"Chave pública: {BOB_PUBLIC_KEY_PATH}")
        print("Nenhum arquivo foi sobrescrito.")
        return False

    print("Gerando par RSA-4096 de TESTE do Bob. Isso pode levar alguns segundos...")

    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    BOB_PRIVATE_KEY_PATH.write_bytes(private_pem)
    BOB_PUBLIC_KEY_PATH.write_bytes(public_pem)

    print("Par RSA-4096 de teste do Bob gerado com sucesso.")
    print(f"Chave privada salva em: {BOB_PRIVATE_KEY_PATH}")
    print(f"Chave pública salva em: {BOB_PUBLIC_KEY_PATH}")
    print("O conteúdo da chave privada não é exibido por segurança.")
    print("Estas chaves são somente para simulação local, não são as chaves reais do Mussatto.")
    return True


def verify_bob_test_keys() -> bool:
    """Confirma que o par de teste do Bob é RSA-4096 e está combinado."""
    if not BOB_PRIVATE_KEY_PATH.exists() or not BOB_PUBLIC_KEY_PATH.exists():
        raise BobTestKeyError(
            "As chaves de teste do Bob estão ausentes. "
            "Gere o par antes de verificar."
        )

    loaded_private = serialization.load_pem_private_key(
        BOB_PRIVATE_KEY_PATH.read_bytes(),
        password=None,
    )
    loaded_public = serialization.load_pem_public_key(
        BOB_PUBLIC_KEY_PATH.read_bytes()
    )

    if not isinstance(loaded_private, RSAPrivateKey):
        raise BobTestKeyError("A chave privada de teste do Bob não é RSA.")
    if not isinstance(loaded_public, RSAPublicKey):
        raise BobTestKeyError("A chave pública de teste do Bob não é RSA.")

    private_size = loaded_private.key_size
    public_size = loaded_public.key_size
    derived_numbers = loaded_private.public_key().public_numbers()
    loaded_numbers = loaded_public.public_numbers()
    keys_match = (
        derived_numbers.n == loaded_numbers.n
        and derived_numbers.e == loaded_numbers.e
    )

    print()
    print("========================================")
    print("   VERIFICAÇÃO DAS CHAVES DE TESTE DO BOB")
    print("========================================")
    print()
    print("Algoritmo: RSA")
    print(f"Tamanho da chave privada: {private_size} bits")
    print(f"Tamanho da chave pública: {public_size} bits")
    print(f"Expoente público: {loaded_numbers.e}")
    print(
        "Chave pública corresponde à privada: "
        f"{'SIM' if keys_match else 'NÃO'}"
    )
    print()

    problems: list[str] = []
    if private_size != RSA_KEY_SIZE:
        problems.append(
            f"A chave privada de teste possui {private_size} bits, "
            f"mas o projeto exige {RSA_KEY_SIZE} bits."
        )
    if public_size != RSA_KEY_SIZE:
        problems.append(
            f"A chave pública de teste possui {public_size} bits, "
            f"mas o projeto exige {RSA_KEY_SIZE} bits."
        )
    if not keys_match:
        problems.append(
            "A chave pública de teste do Bob não corresponde à privada."
        )

    if problems:
        print("Status: PAR RSA DE TESTE INVÁLIDO")
        for problem in problems:
            print(f"  - {problem}")
        print("========================================")
        raise BobTestKeyError(" ".join(problems))

    print("Status: PAR RSA-4096 DE TESTE DO BOB VÁLIDO")
    print("========================================")
    return True


def main() -> None:
    _configure_stdout()
    try:
        generate_bob_test_keys()
        verify_bob_test_keys()
    except BobTestKeyError as error:
        print()
        print(f"Erro: {error}")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
