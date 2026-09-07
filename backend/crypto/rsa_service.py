"""Serviço de criptografia e descriptografia assimétrica RSA-4096 com OAEP e SHA-256.

Fundamentação Criptográfica:
    O RSA (Rivest-Shamir-Adleman) é um criptossistema de chave pública fundamentado
    na dificuldade computacional da fatoração de inteiros grandes (problema RSA).
    
    1. Dimensão das Chaves e Bloco Cifrado:
       - Módulo RSA: n = p * q, com tamanho de 4096 bits.
       - Comprimento do bloco cifrado em bytes: k = 4096 / 8 = 512 bytes.
       - Toda operação de cifragem RSA-4096 resulta invariavelmente em um bloco de 512 bytes.

    2. Esquema de Preenchimento OAEP (Optimal Asymmetric Encryption Padding):
       - Utilizado conforme o padrão PKCS#1 v2.2 (RFC 8017).
       - O RSA "puro" (textbook RSA) é determinístico e vulnerável a múltiplos ataques
         (ex.: ataque de texto em claro escolhido, homomorfismo multiplicativo).
       - O OAEP introduz aleatoriedade através de uma rede de Feistel assimétrica
         alimentada por uma função geradora de máscaras (MGF1) e uma função de hash (SHA-256).
       - Propriedade Probabilística: Cifrar a mesma mensagem repetidas vezes produz
         ciphertexts completamente distintos a cada execução, inviabilizando ataques
         de análise de frequência e busca em dicionário.

    3. Capacidade Máxima do Texto em Claro (Payload Útil):
       - Pela especificação RFC 8017 para RSA-OAEP, a capacidade máxima do plaintext é:
             Tamanho Máximo = k - 2 * hLen - 2
         onde:
             k    = tamanho do módulo em bytes = 512 bytes
             hLen = tamanho da saída do hash SHA-256 = 32 bytes
         Portanto:
             Tamanho Máximo = 512 - 2 * 32 - 2 = 512 - 64 - 2 = 446 bytes UTF-8.

    4. Codificação Base64:
       - Base64 NÃO é criptografia, mas sim um esquema de codificação binário-para-texto (RFC 4648).
       - Seu propósito no projeto é encapsular os 512 bytes binários do ciphertext
         em caracteres seguros ASCII para inclusão nos pacotes JSON do protocolo de rede.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .key_manager import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

# Limite estrito de bytes UTF-8 para plaintext: 512 - 2*32 - 2 = 446 bytes
RSA_OAEP_SHA256_MAX_BYTES = 446

# Tamanho exato do bloco criptografado gerado por RSA-4096 (4096 bits / 8 = 512 bytes)
RSA_CIPHERTEXT_BYTES = 512

KeyPath = str | Path


class RsaServiceError(Exception):
    """Exceção customizada para erros de validação, cifragem ou decifragem RSA."""


def _as_path(path: KeyPath) -> Path:
    """Converte argumentos em str ou Path para um objeto pathlib.Path normalizado.

    Args:
        path: Caminho no formato str ou Path.

    Returns:
        Path: Instância normalizada de pathlib.Path.
    """
    return Path(path)


def _oaep_padding() -> padding.OAEP:
    """Instancia a estrutura de padding seguro OAEP parametrizada com SHA-256.

    Configura o preenchimento com:
        - MGF (Mask Generation Function): MGF1 com SHA-256.
        - Algoritmo de Hash principal: SHA-256 (32 bytes de digest).
        - Label opcional: None.

    Returns:
        padding.OAEP: Objeto de preenchimento pronto para cifragem ou decifragem.
    """
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _encode_plaintext(message: str) -> bytes:
    """Valida o conteúdo e a dimensão da mensagem em claro, convertendo-a para UTF-8.

    Verificações Realizadas:
        1. Garantia de que a mensagem é uma cadeia de caracteres (str).
        2. Bloqueio de mensagens vazias.
        3. Validação do limite estrito de 446 bytes da especificação RSA-4096 OAEP/SHA-256.

    Args:
        message: Texto em claro a ser validado e convertido.

    Returns:
        bytes: Sequência de bytes codificada em UTF-8.

    Raises:
        RsaServiceError: Se o tipo for inválido, se o texto estiver vazio ou se
            ultrapassar 446 bytes UTF-8.
    """
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
    """Carrega uma chave pública RSA serializada em formato PEM a partir de arquivo em disco.

    Args:
        path: Caminho até o arquivo PEM da chave pública.

    Returns:
        RSAPublicKey: Instância da chave pública RSA carregada.

    Raises:
        RsaServiceError: Se o arquivo não existir, estiver corrompido ou não for uma chave RSA.
    """
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
    """Carrega uma chave privada RSA a partir de um arquivo PEM em disco.

    Garantia de Confidencialidade:
        O material criptográfico secreto da chave privada é manipulado exclusivamente
        pela biblioteca cryptography em memória nativa e nunca é exposto em texto.

    Args:
        path: Caminho até o arquivo PEM da chave privada.

    Returns:
        RSAPrivateKey: Instância da chave privada RSA carregada.

    Raises:
        RsaServiceError: Se o arquivo não existir, estiver corrompido ou não for RSA.
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
    """Desserializa uma chave pública RSA recebida em memória via rede (formato PEM).

    Esta função é utilizada no handshake TCP para instanciar a chave pública do peer
    diretamente a partir do payload recebido, sem necessidade de gravá-la em disco.
    Possui checagem ativa para impedir o recebimento acidental de chaves privadas.

    Args:
        pem_data: Chave pública codificada em PEM como string ou bytes.

    Returns:
        RSAPublicKey: Instância da chave pública RSA desserializada.

    Raises:
        RsaServiceError: Se os dados estiverem vazios, contiverem marcadores de chave privada,
            estiverem malformados ou não pertencerem ao algoritmo RSA.
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
    """Verifica se a chave pública fornecida é estritamente RSA com módulo de 4096 bits.

    Atua como validação de segurança ao receber a chave remota pela rede, rejeitando
    chaves de tamanhos inadequados ou algoritmos não autorizados.

    Args:
        public_key: Instância de RSAPublicKey a ser inspecionada.

    Raises:
        RsaServiceError: Se não for RSA ou se o tamanho for diferente de 4096 bits.
    """
    if not isinstance(public_key, RSAPublicKey):
        raise RsaServiceError("A chave pública não é RSA.")
    if public_key.key_size != 4096:
        raise RsaServiceError(
            f"A chave pública possui {public_key.key_size} bits, "
            "mas o projeto exige RSA-4096."
        )


def read_public_pem_text(path: KeyPath) -> str:
    """Lê o arquivo PEM da chave pública como texto UTF-8 para transmissão em pacotes TCP.

    Inclui salvaguarda para certificar que o arquivo não contém blocos de chave privada.

    Args:
        path: Caminho até a chave pública.

    Returns:
        str: Texto PEM da chave pública.

    Raises:
        RsaServiceError: Se o arquivo não existir ou contiver marcadores de chave privada.
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
    """Criptografa uma mensagem em claro utilizando um objeto de chave pública em memória.

    Aplica a codificação UTF-8, o padding OAEP (SHA-256 / MGF1) e a exponenciação modular RSA:
        c = m_padded^e mod n

    Args:
        message: Texto em claro a ser criptografado (máx. 446 bytes UTF-8).
        public_key: Objeto RSAPublicKey (normalmente a chave pública do interlocutor).

    Returns:
        bytes: Bloco cifrado resultante de exatamente 512 bytes.

    Raises:
        RsaServiceError: Se a mensagem for inválida, exceder o tamanho ou a chave não for válida.
    """
    if not isinstance(public_key, RSAPublicKey):
        raise RsaServiceError("É necessária uma chave pública RSA para criptografar.")

    plaintext = _encode_plaintext(message)
    return public_key.encrypt(plaintext, _oaep_padding())


def load_public_key() -> RSAPublicKey:
    """Carrega a chave pública PEM padrão local (Alice) definida em key_manager.

    Returns:
        RSAPublicKey: Chave pública carregada.
    """
    return load_public_key_from_file(PUBLIC_KEY_PATH)


def load_private_key() -> RSAPrivateKey:
    """Carrega a chave privada PEM padrão local (Alice) definida em key_manager.

    Returns:
        RSAPrivateKey: Chave privada carregada.
    """
    return load_private_key_from_file(PRIVATE_KEY_PATH)


def encrypt_message_with_public_key(message: str, public_key_path: KeyPath) -> bytes:
    """Criptografa uma mensagem em claro utilizando a chave pública localizada no caminho indicado.

    Args:
        message: Texto em claro (máx. 446 bytes).
        public_key_path: Caminho do arquivo PEM da chave pública do destinatário.

    Returns:
        bytes: Bloco criptografado de 512 bytes.
    """
    plaintext = _encode_plaintext(message)
    public_key = load_public_key_from_file(public_key_path)
    return public_key.encrypt(plaintext, _oaep_padding())


def decrypt_message_with_private_key(
    encrypted_message: bytes,
    private_key_path: KeyPath,
) -> str:
    """Descriptografa um bloco RSA de 512 bytes utilizando a chave privada indicada.

    Processo Criptográfico:
        1. Executa a operação privada RSA: m_padded = c^d mod n.
        2. Verifica e remove o preenchimento probabilístico OAEP com validação SHA-256.
        3. Decodifica os bytes recuperados em texto UTF-8.

    Se a chave privada não corresponder exatamente à chave pública utilizada na cifragem,
    o desempacotamento do preenchimento OAEP falhará matematicamente, levantando ValueError.

    Args:
        encrypted_message: Bloco cifrado em bytes (esperado: 512 bytes).
        private_key_path: Caminho até a chave privada do participante destinatário.

    Returns:
        str: Texto em claro original recuperado.

    Raises:
        RsaServiceError: Se os dados forem vazios/inválidos, se a decifragem falhar
            (chave incorreta ou mensagem corrompida), ou se os bytes não formarem UTF-8 válido.
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
    """Criptografa a mensagem com a chave pública local padrão (Alice).

    Mantida para retrocompatibilidade com os testes didáticos locais (test_rsa.py).

    Args:
        message: Texto em claro a ser cifrado.

    Returns:
        bytes: Bloco de 512 bytes cifrado.
    """
    return encrypt_message_with_public_key(message, PUBLIC_KEY_PATH)


def decrypt_message(encrypted_message: bytes) -> str:
    """Descriptografa o bloco cifrado com a chave privada local padrão (Alice).

    Mantida para retrocompatibilidade com os testes didáticos locais (test_rsa.py).

    Args:
        encrypted_message: Bloco cifrado de 512 bytes.

    Returns:
        str: Texto em claro original decifrado.
    """
    return decrypt_message_with_private_key(encrypted_message, PRIVATE_KEY_PATH)


def public_key_fingerprint(pem_text: str) -> str:
    """Calcula a impressão digital criptográfica (fingerprint SHA-256) de uma chave pública PEM.

    Gera uma representação hexadecimal formatada (ex.: 'A1:B2:C3:D4:E5:F6:07:08')
    para permitir a verificação visual imediata da chave pública pelos usuários,
    sem expor ou poluir a interface com o texto PEM completo.

    Args:
        pem_text: Conteúdo textual da chave pública em PEM.

    Returns:
        str: Impressão digital formatada com os 8 primeiros bytes em pares hexadecimais.
    """
    digest = hashlib.sha256(pem_text.encode("utf-8")).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, 16, 2))


def encrypted_bytes_to_base64(encrypted_data: bytes) -> str:
    """Codifica o bloco binário cifrado RSA em uma string Base64 (RFC 4648).

    Importante:
        Base64 é exclusivamente uma representação textual e NÃO adiciona segurança criptográfica.
        Sua finalidade é viabilizar o transporte do ciphertext binário de 512 bytes em estruturas
        textuais (JSON, logs e telas de interface gráfica).

    Args:
        encrypted_data: Bytes brutos do bloco criptografado.

    Returns:
        str: Cadeia de caracteres ASCII representando os dados em Base64.

    Raises:
        RsaServiceError: Se os dados de entrada não forem bytes.
    """
    if not isinstance(encrypted_data, (bytes, bytearray)):
        raise RsaServiceError("Os dados criptografados precisam estar em bytes.")
    return base64.b64encode(bytes(encrypted_data)).decode("ascii")


def base64_to_encrypted_bytes(encoded_data: str) -> bytes:
    """Decodifica uma representação textual Base64 de volta para os bytes binários do bloco RSA.

    Args:
        encoded_data: String Base64 contendo os dados cifrados.

    Returns:
        bytes: Sequência binária original decodificada.

    Raises:
        RsaServiceError: Se a string for vazia, inválida ou contiver caracteres fora do padrão Base64.
    """
    if not isinstance(encoded_data, str) or encoded_data.strip() == "":
        raise RsaServiceError("A representação Base64 não pode ser vazia.")

    try:
        return base64.b64decode(encoded_data, validate=True)
    except (ValueError, TypeError) as error:
        raise RsaServiceError(
            f"A representação Base64 é inválida: {error}"
        ) from error

