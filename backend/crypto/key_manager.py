"""Gerenciador das chaves RSA-4096 da Alice.

Este módulo gera, armazena e verifica o par de chaves da Alice.
Nenhuma chave é enviada pela rede nesta etapa.

Esquema conceitual da atividade (ainda não implementado):

    Bob → mensagem para Alice
        Bob cifra com a CHAVE PÚBLICA da Alice.
        Alice decifra com a CHAVE PRIVADA da Alice.

    Alice → mensagem para Bob
        Alice cifra com a CHAVE PÚBLICA do Bob.
        Bob decifra com a CHAVE PRIVADA do Bob.

A chave privada permanece apenas neste computador (Alice).
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

# Diretório base do backend: .../ChatCriptografado/backend
BACKEND_DIR = Path(__file__).resolve().parent.parent

# Diretório das chaves: pasta local onde os arquivos PEM da Alice são
# gravados. Não deve ser compartilhada com outros computadores.
KEYS_DIR = BACKEND_DIR / "keys"

# Chave privada: segredo da Alice. Serve para descriptografar mensagens
# enviadas a ela. Nunca deve ser compartilhada, impressa ou enviada ao Git.
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"

# Chave pública: pode ser compartilhada futuramente com Bob, para que ele
# consiga criptografar mensagens destinadas à Alice.
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"

# 4096 bits oferece margem de segurança maior do que 2048 bits, ainda
# comum em atividades acadêmicas e em recomendações atuais para RSA.
RSA_KEY_SIZE = 4096

# 65537 (2^16 + 1) é o expoente público padrão do RSA: ímpar, primo e
# eficiente na cifragem, sem enfraquecer o esquema quando o módulo é grande.
RSA_PUBLIC_EXPONENT = 65537


class KeyManagerError(Exception):
    """Erro no gerenciamento ou na verificação das chaves RSA da Alice."""


def keys_already_exist() -> bool:
    """Retorna True se a chave privada ou a chave pública já existirem.

    Verificamos antes de gerar um novo par para não sobrescrever uma
    chave privada já criada. Perder a chave privada da Alice impediria
    descriptografar mensagens futuras destinadas a este computador.
    """
    return PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists()


def generate_rsa_keys() -> bool:
    """Gera um par RSA-4096 da Alice e o salva em PEM, se ainda não existir.

    Retorna True se um novo par foi gerado e False se as chaves já existiam.

    O formato PEM (Privacy-Enhanced Mail) é um texto ASCII delimitado por
    cabeçalhos BEGIN/END, conveniente para armazenar chaves em arquivo.

    PKCS8 é um padrão de encapsulamento da chave privada. Aqui usamos
    PKCS8 sem senha (NoEncryption) porque a proteção, nesta etapa, é
    manter o arquivo somente no computador da Alice e fora do Git.
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if keys_already_exist():
        print("As chaves RSA já existem.")
        print(f"Chave privada (não será exibida): {PRIVATE_KEY_PATH}")
        print(f"Chave pública: {PUBLIC_KEY_PATH}")
        print("Nenhum arquivo foi sobrescrito.")
        return False

    print("Gerando par RSA-4096 da Alice. Isso pode levar alguns segundos...")

    # A chave privada é gerada primeiro; a pública é derivada dela.
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

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)

    print("Par RSA-4096 gerado com sucesso.")
    print(f"Chave privada salva em: {PRIVATE_KEY_PATH}")
    print(f"Chave pública salva em: {PUBLIC_KEY_PATH}")
    print("O conteúdo da chave privada não é exibido por segurança.")
    return True


def _load_private_key() -> RSAPrivateKey:
    """Carrega a chave privada PEM do disco, sem imprimir o conteúdo."""
    try:
        loaded_key = serialization.load_pem_private_key(
            PRIVATE_KEY_PATH.read_bytes(),
            password=None,
        )
    except ValueError as error:
        raise KeyManagerError(
            f"O arquivo da chave privada é inválido: {error}"
        ) from error

    if not isinstance(loaded_key, RSAPrivateKey):
        raise KeyManagerError(
            "A chave privada carregada não é RSA. "
            "Nenhum arquivo será substituído automaticamente."
        )

    return loaded_key


def _load_public_key() -> RSAPublicKey:
    """Carrega a chave pública PEM do disco."""
    try:
        loaded_key = serialization.load_pem_public_key(
            PUBLIC_KEY_PATH.read_bytes()
        )
    except ValueError as error:
        raise KeyManagerError(
            f"O arquivo da chave pública é inválido: {error}"
        ) from error

    if not isinstance(loaded_key, RSAPublicKey):
        raise KeyManagerError(
            "A chave pública carregada não é RSA. "
            "Nenhum arquivo será substituído automaticamente."
        )

    return loaded_key


def _public_keys_match(private_key: RSAPrivateKey, public_key: RSAPublicKey) -> bool:
    """Compara o módulo n e o expoente e das duas chaves públicas RSA."""
    derived_numbers = private_key.public_key().public_numbers()
    loaded_numbers = public_key.public_numbers()
    return (
        derived_numbers.n == loaded_numbers.n
        and derived_numbers.e == loaded_numbers.e
    )


def verify_rsa_keys() -> bool:
    """Verifica existência, algoritmo, tamanho e correspondência do par RSA.

    Confirma que ambas as chaves têm exatamente 4096 bits e que a chave
    pública em disco é a mesma derivada da chave privada da Alice.

    Em caso de problema, a mensagem é exibida em português e os arquivos
    não são apagados nem substituídos.
    """
    private_found = PRIVATE_KEY_PATH.exists()
    public_found = PUBLIC_KEY_PATH.exists()

    print()
    print("========================================")
    print("       VERIFICAÇÃO DAS CHAVES RSA")
    print("========================================")
    print()
    print(f"Chave privada encontrada: {'SIM' if private_found else 'NÃO'}")
    print(f"Chave pública encontrada: {'SIM' if public_found else 'NÃO'}")
    print()

    if not private_found or not public_found:
        missing: list[str] = []
        if not private_found:
            missing.append(str(PRIVATE_KEY_PATH))
        if not public_found:
            missing.append(str(PUBLIC_KEY_PATH))
        print("Status: PAR RSA INCOMPLETO")
        print("Arquivo(s) ausente(s):")
        for path in missing:
            print(f"  - {path}")
        print()
        print("========================================")
        raise KeyManagerError(
            "Não foi possível verificar o par RSA porque um ou ambos "
            "os arquivos de chave estão ausentes."
        )

    private_key = _load_private_key()
    public_key = _load_public_key()

    private_size = private_key.key_size
    public_size = public_key.key_size
    public_exponent = public_key.public_numbers().e
    keys_match = _public_keys_match(private_key, public_key)

    print("Algoritmo: RSA")
    print(f"Tamanho da chave privada: {private_size} bits")
    print(f"Tamanho da chave pública: {public_size} bits")
    print(f"Expoente público: {public_exponent}")
    print()
    print(
        "Chave pública corresponde à privada: "
        f"{'SIM' if keys_match else 'NÃO'}"
    )
    print()

    problems: list[str] = []
    if private_size != RSA_KEY_SIZE:
        problems.append(
            f"A chave privada possui {private_size} bits, "
            f"mas o projeto exige {RSA_KEY_SIZE} bits."
        )
    if public_size != RSA_KEY_SIZE:
        problems.append(
            f"A chave pública possui {public_size} bits, "
            f"mas o projeto exige {RSA_KEY_SIZE} bits."
        )
    if not keys_match:
        problems.append(
            "A chave pública em disco não corresponde à chave pública "
            "derivada da chave privada."
        )

    if problems:
        print("Status: PAR RSA INVÁLIDO")
        print()
        print("Problemas encontrados:")
        for problem in problems:
            print(f"  - {problem}")
        print()
        print("Nenhum arquivo foi substituído automaticamente.")
        print("========================================")
        raise KeyManagerError(" ".join(problems))

    print("Status: PAR RSA-4096 VÁLIDO")
    print()
    print("========================================")
    return True


def main() -> None:
    """Gera o par RSA se necessário e, em seguida, verifica as chaves."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

    try:
        generate_rsa_keys()
        verify_rsa_keys()
    except KeyManagerError as error:
        print()
        print(f"Erro: {error}")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
