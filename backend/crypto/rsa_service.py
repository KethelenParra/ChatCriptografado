"""Criptografia e descriptografia local de mensagens com RSA-4096.

RSA é um algoritmo de criptografia assimétrica: usa um par de chaves.
A chave pública pode ser compartilhada. A chave privada deve permanecer
secreta com o respectivo dono.

Para enviar informação para Alice, cifra-se com a chave pública dela.
Somente Alice recupera a mensagem com a chave privada correspondente.

Para enviar informação para Bob, cifra-se com a chave pública dele.
Somente Bob recupera a mensagem com a chave privada correspondente.

OAEP (Optimal Asymmetric Encryption Padding) adiciona padding seguro
à operação RSA, incluindo aleatoriedade. SHA-256 é o hash usado no OAEP.

RSA-4096 produz um bloco cifrado de 4096 bits, equivalente a 512 bytes.
Por isso, a mensagem em si tem limite de tamanho (cerca de 446 bytes
com OAEP e SHA-256). Não implementamos cifra híbrida nesta etapa.

Base64 NÃO é criptografia. Serve somente como representação textual
dos bytes criptografados, para exibição e transporte de dados binários.
A segurança vem do RSA, não do Base64.

As funções sem caminho explícito continuam usando as chaves da Alice,
para preservar o teste anterior (test_rsa.py).
"""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .key_manager import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

# RSA-4096 cifra um bloco de 512 bytes. Com OAEP + SHA-256, o espaço
# útil da mensagem é: 512 - 2 * 32 - 2 = 446 bytes UTF-8.
RSA_OAEP_SHA256_MAX_BYTES = 446
RSA_CIPHERTEXT_BYTES = 512

KeyPath = str | Path


class RsaServiceError(Exception):
    """Erro na criptografia ou na descriptografia RSA."""


def _as_path(path: KeyPath) -> Path:
    """Normaliza o caminho informado para pathlib.Path."""
    return Path(path)


def _oaep_padding() -> padding.OAEP:
    """Monta o padding OAEP com SHA-256, usado na cifra e na decifra."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _encode_plaintext(message: str) -> bytes:
    """Valida a mensagem e a converte para bytes UTF-8."""
    if not isinstance(message, str):
        raise RsaServiceError("A mensagem precisa ser um texto (string).")

    if message == "":
        raise RsaServiceError("A mensagem não pode ser vazia.")

    plaintext = message.encode("utf-8")
    if len(plaintext) > RSA_OAEP_SHA256_MAX_BYTES:
        raise RsaServiceError(
            "A mensagem excede o limite permitido para RSA-4096 com OAEP/SHA-256."
        )
    return plaintext


def load_public_key_from_file(path: KeyPath) -> RSAPublicKey:
    """Carrega uma chave pública RSA a partir de um arquivo PEM."""
    key_path = _as_path(path)
    if not key_path.exists():
        raise RsaServiceError(
            f"A chave pública não foi encontrada em: {key_path}"
        )

    try:
        loaded_key = serialization.load_pem_public_key(key_path.read_bytes())
    except (ValueError, TypeError) as error:
        raise RsaServiceError(
            f"O arquivo da chave pública é inválido: {error}"
        ) from error
    except InvalidKey as error:
        raise RsaServiceError(
            f"A chave pública carregada é inválida: {error}"
        ) from error

    if not isinstance(loaded_key, RSAPublicKey):
        raise RsaServiceError("A chave pública carregada não é RSA.")

    return loaded_key


def load_private_key_from_file(path: KeyPath) -> RSAPrivateKey:
    """Carrega uma chave privada RSA a partir de um arquivo PEM.

    O conteúdo da chave privada nunca é impresso.
    """
    key_path = _as_path(path)
    if not key_path.exists():
        raise RsaServiceError(
            f"A chave privada não foi encontrada em: {key_path}"
        )

    try:
        loaded_key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=None,
        )
    except (ValueError, TypeError) as error:
        raise RsaServiceError(
            f"O arquivo da chave privada é inválido: {error}"
        ) from error
    except InvalidKey as error:
        raise RsaServiceError(
            f"A chave privada carregada é inválida: {error}"
        ) from error

    if not isinstance(loaded_key, RSAPrivateKey):
        raise RsaServiceError("A chave privada carregada não é RSA.")

    return loaded_key


def load_public_key_from_pem(pem_data: str | bytes) -> RSAPublicKey:
    """Carrega uma chave pública RSA a partir de texto ou bytes PEM.

    Usada quando a chave pública chega pela rede e permanece só em
    memória, sem ser gravada em disco.
    """
    if isinstance(pem_data, str):
        if pem_data.strip() == "":
            raise RsaServiceError("O PEM da chave pública está vazio.")
        if "PRIVATE KEY" in pem_data:
            raise RsaServiceError(
                "O material recebido parece uma chave privada. "
                "Somente chaves públicas podem ser compartilhadas."
            )
        pem_bytes = pem_data.encode("utf-8")
    elif isinstance(pem_data, (bytes, bytearray)):
        pem_bytes = bytes(pem_data)
        if b"PRIVATE KEY" in pem_bytes:
            raise RsaServiceError(
                "O material recebido parece uma chave privada. "
                "Somente chaves públicas podem ser compartilhadas."
            )
    else:
        raise RsaServiceError("O PEM da chave pública precisa ser texto ou bytes.")

    try:
        loaded_key = serialization.load_pem_public_key(pem_bytes)
    except (ValueError, TypeError) as error:
        raise RsaServiceError(
            f"O PEM da chave pública é inválido: {error}"
        ) from error
    except InvalidKey as error:
        raise RsaServiceError(
            f"A chave pública em PEM é inválida: {error}"
        ) from error

    if not isinstance(loaded_key, RSAPublicKey):
        raise RsaServiceError("A chave pública carregada não é RSA.")

    return loaded_key


def validate_rsa_4096_public_key(public_key: RSAPublicKey) -> None:
    """Confirma que a chave pública é RSA de exatamente 4096 bits."""
    if not isinstance(public_key, RSAPublicKey):
        raise RsaServiceError("A chave pública não é RSA.")
    if public_key.key_size != 4096:
        raise RsaServiceError(
            f"A chave pública possui {public_key.key_size} bits, "
            "mas o projeto exige RSA-4096."
        )


def read_public_pem_text(path: KeyPath) -> str:
    """Lê o arquivo PEM da chave pública como texto, para envio pela rede.

    A chave privada nunca é lida por esta função.
    """
    key_path = _as_path(path)
    if not key_path.exists():
        raise RsaServiceError(
            f"A chave pública não foi encontrada em: {key_path}"
        )

    pem_text = key_path.read_text(encoding="utf-8")
    if "PRIVATE KEY" in pem_text:
        raise RsaServiceError(
            "Tentativa de ler uma chave privada como pública foi bloqueada."
        )
    load_public_key_from_pem(pem_text)
    return pem_text


def encrypt_message_with_public_key_object(
    message: str,
    public_key: RSAPublicKey,
) -> bytes:
    """Cifra a mensagem com um objeto de chave pública já carregado.

    A chave pública do destinatário pode ter sido recebida pela conexão
    TCP e mantida apenas em memória.
    """
    if not isinstance(public_key, RSAPublicKey):
        raise RsaServiceError("É necessária uma chave pública RSA para criptografar.")

    plaintext = _encode_plaintext(message)
    return public_key.encrypt(plaintext, _oaep_padding())


def load_public_key() -> RSAPublicKey:
    """Carrega a chave pública PEM da Alice."""
    return load_public_key_from_file(PUBLIC_KEY_PATH)


def load_private_key() -> RSAPrivateKey:
    """Carrega a chave privada PEM da Alice."""
    return load_private_key_from_file(PRIVATE_KEY_PATH)


def encrypt_message_with_public_key(message: str, public_key_path: KeyPath) -> bytes:
    """Cifra a mensagem com a chave pública indicada (RSA-OAEP/SHA-256)."""
    plaintext = _encode_plaintext(message)
    public_key = load_public_key_from_file(public_key_path)
    return public_key.encrypt(plaintext, _oaep_padding())


def decrypt_message_with_private_key(
    encrypted_message: bytes,
    private_key_path: KeyPath,
) -> str:
    """Decifra os bytes RSA com a chave privada indicada.

    Se a chave privada não corresponder à pública usada na cifra,
    a biblioteca cryptography lança ValueError. Essa falha é
    encapsulada em RsaServiceError, preservando a causa original.
    """
    if not isinstance(encrypted_message, (bytes, bytearray)):
        raise RsaServiceError(
            "A mensagem criptografada precisa estar em bytes."
        )

    if len(encrypted_message) == 0:
        raise RsaServiceError("A mensagem criptografada não pode ser vazia.")

    private_key = load_private_key_from_file(private_key_path)
    try:
        plaintext = private_key.decrypt(bytes(encrypted_message), _oaep_padding())
    except ValueError as error:
        raise RsaServiceError(
            "Falha na descriptografia RSA. "
            "A mensagem pode estar corrompida ou ter sido cifrada "
            f"com outra chave. Detalhe técnico: {error}"
        ) from error

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RsaServiceError(
            f"Os bytes descriptografados não formam um texto UTF-8 válido: {error}"
        ) from error


def encrypt_message(message: str) -> bytes:
    """Cifra a mensagem com a chave pública da Alice (RSA-OAEP/SHA-256)."""
    return encrypt_message_with_public_key(message, PUBLIC_KEY_PATH)


def decrypt_message(encrypted_message: bytes) -> str:
    """Decifra os bytes RSA com a chave privada da Alice."""
    return decrypt_message_with_private_key(encrypted_message, PRIVATE_KEY_PATH)


def encrypted_bytes_to_base64(encrypted_data: bytes) -> str:
    """Converte o bloco RSA (bytes) para uma string Base64.

    Base64 NÃO é criptografia. É apenas uma representação textual dos
    bytes criptografados, permitindo exibição e transporte de dados
    binários. A segurança vem do RSA, não do Base64.
    """
    if not isinstance(encrypted_data, (bytes, bytearray)):
        raise RsaServiceError("Os dados criptografados precisam estar em bytes.")
    return base64.b64encode(bytes(encrypted_data)).decode("ascii")


def base64_to_encrypted_bytes(encoded_data: str) -> bytes:
    """Converte a string Base64 de volta para os bytes RSA originais."""
    if not isinstance(encoded_data, str) or encoded_data.strip() == "":
        raise RsaServiceError("A representação Base64 não pode ser vazia.")

    try:
        return base64.b64decode(encoded_data, validate=True)
    except (ValueError, TypeError) as error:
        raise RsaServiceError(
            f"A representação Base64 é inválida: {error}"
        ) from error
