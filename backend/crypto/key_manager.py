"""Gerenciador local de chaves assimétricas RSA-4096.

Este módulo é responsável pelo ciclo de vida local do par de chaves RSA:
geração do par, persistência segura no disco em formato PEM e verificação
de integridade e conformidade com os parâmetros criptográficos exigidos.

Conceito de Criptografia Assimétrica no Projeto:
    A comunicação segura ponto a ponto entre Alice e Bob apoia-se no princípio
    de que cada participante gera e custodia exclusivamente o seu próprio par
    de chaves (chave pública e chave privada).
    
    1. Chave Privada (private_key.pem):
       - Permanece ESTRITAMENTE confidencial na máquina de quem a gerou.
       - Nunca é transmitida pela rede, impressa em logs ou incluída em controle de versão.
       - Utilizada unicamente para descriptografar mensagens destinadas a este participante.
       
    2. Chave Pública (public_key.pem):
       - Pode ser compartilhada abertamente com o outro participante pelo canal TCP.
       - Utilizada pelo interlocutor para criptografar mensagens destinadas a este participante.

Fluxo Bidirecional da Atividade:
    Bob  → Alice: Bob cifra com a pública da Alice; Alice decifra com sua privada.
    Alice → Bob:  Alice cifra com a pública do Bob; Bob decifra com sua privada.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

# Diretório base do backend: .../ChatCriptografado/backend
BACKEND_DIR = Path(__file__).resolve().parent.parent

# Diretório das chaves: armazena os arquivos PEM locais da máquina em execução.
# Este diretório está explicitamente protegido no .gitignore.
KEYS_DIR = BACKEND_DIR / "keys"

# Caminho da chave privada local: arquivo de máxima confidencialidade.
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"

# Caminho da chave pública local: distribuída durante o handshake TCP.
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"

# Tamanho do módulo RSA em bits. 4096 bits oferece um nível de segurança elevado
# contra ataques de fatoração inteira (equivalente a ~140 bits de segurança simétrica).
RSA_KEY_SIZE = 4096

# Expoente público padrão da indústria (Fermat F_4 = 2^16 + 1 = 65537).
# Apresenta peso de Hamming baixo (apenas dois bits 1 em binário: 10000000000000001_2),
# garantindo exponenciação modular rápida sem comprometer a segurança.
RSA_PUBLIC_EXPONENT = 65537


class KeyManagerError(Exception):
    """Exceção customizada para erros no gerenciamento ou verificação de chaves RSA."""


def keys_already_exist() -> bool:
    """Verifica se qualquer um dos arquivos do par RSA já existe no disco.

    Essa verificação atua como salvaguarda para evitar a sobreescrita
    acidental de uma chave privada preexistente. Caso a chave privada fosse
    sobrescrita, todas as mensagens anteriormente cifradas para este participante
    tornar-se-iam permanentemente irrecuperáveis.

    Returns:
        bool: True se private_key.pem ou public_key.pem já existirem no diretório de chaves.
    """
    return PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists()


def generate_rsa_keys() -> bool:
    """Gera um par de chaves RSA-4096 e o serializa em arquivos PEM, se ainda não existir.

    Processo Criptográfico:
        1. Geração probabilística de dois números primos grandes distintos (p e q).
        2. Cálculo do módulo RSA n = p * q (4096 bits) e da função totiente phi(n).
        3. Associação ao expoente público e = 65537 e dedução do expoente privado d = e^-1 mod phi(n).
        4. Derivação da chave pública correspondente a partir do objeto da chave privada.
        5. Serialização da chave privada no padrão PKCS#8 (sem criptografia de senha local,
           garantida pelo controle de acesso do sistema de arquivos e .gitignore).
        6. Serialização da chave pública no padrão SubjectPublicKeyInfo (X.509).

    Returns:
        bool: True se um novo par foi gerado com sucesso; False se as chaves já existiam.

    Raises:
        OSError: Caso ocorra falha de permissão ou I/O ao persistir os arquivos em disco.
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if keys_already_exist():
        print("As chaves RSA já existem.")
        print(f"Chave privada (não será exibida): {PRIVATE_KEY_PATH}")
        print(f"Chave pública: {PUBLIC_KEY_PATH}")
        print("Nenhum arquivo foi sobrescrito.")
        return False

    print("Gerando par RSA-4096 da Alice. Isso pode levar alguns segundos...")

    # Geração dos primos p e q e cálculo dos parâmetros assimétricos RSA
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()

    # Formatação PKCS#8 para a chave privada
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Formatação SubjectPublicKeyInfo (SPKI) para a chave pública
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
    """Carrega a chave privada local a partir do arquivo PEM persistido em disco.

    Por razões estritas de segurança, o conteúdo bruto da chave privada
    nunca é exposto ou retornado em formato textual.

    Returns:
        RSAPrivateKey: Instância da chave privada RSA carregada e pronta para operações.

    Raises:
        KeyManagerError: Caso o arquivo esteja corrompido ou o algoritmo não seja RSA.
    """
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
    """Carrega a chave pública local a partir do arquivo PEM persistido em disco.

    Returns:
        RSAPublicKey: Instância da chave pública RSA carregada.

    Raises:
        KeyManagerError: Caso o arquivo esteja corrompido ou o algoritmo não seja RSA.
    """
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
    """Verifica matematicamente se a chave pública fornecida corresponde à chave privada.

    Compara o módulo 'n' e o expoente público 'e' derivados da chave privada
    com os parâmetros públicos da chave armazenada em disco.

    Args:
        private_key: Instância da chave privada RSA.
        public_key: Instância da chave pública RSA.

    Returns:
        bool: True se o módulo e o expoente forem estritamente idênticos.
    """
    derived_numbers = private_key.public_key().public_numbers()
    loaded_numbers = public_key.public_numbers()
    return (
        derived_numbers.n == loaded_numbers.n
        and derived_numbers.e == loaded_numbers.e
    )


def verify_rsa_keys() -> bool:
    """Executa a auditoria completa do par de chaves RSA local.

    Validações Realizadas:
        1. Existência física dos dois arquivos de chave (privada e pública).
        2. Conformidade do algoritmo (estritamente RSA).
        3. Tamanho exato de 4096 bits para ambas as chaves.
        4. Correspondência matemática entre o par de chaves.

    Returns:
        bool: True se o par de chaves estiver íntegro, válido e em conformidade.

    Raises:
        KeyManagerError: Caso qualquer um dos testes de conformidade falhe.
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
    """Ponto de entrada de linha de comando para geração e auditoria do par RSA."""
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

