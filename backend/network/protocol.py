"""Protocolo de enquadramento (framing) e serialização de dados sobre TCP Socket.

Fundamentação de Redes e Protocolos:
    O protocolo TCP (Transmission Control Protocol, RFC 793) opera na camada de transporte
    como um fluxo contínuo e não estruturado de bytes (byte-stream). Ao contrário de protocolos
    orientados a datagramas (como UDP), o TCP não preserva os limites de aplicação das mensagens.
    
    Problema do Streaming TCP:
        - Fragmentação: Uma chamada `sendall()` pode ser dividida em múltiplos segmentos TCP pelo kernel.
        - Aglutinação: Várias chamadas `sendall()` consecutivas podem ser agregadas em um único segmento
          (por exemplo, através do algoritmo de Nagle).
        - Consequência: Uma simples chamada `recv(buffer_size)` pode retornar apenas uma fração do pacote
          ou concatenar partes de mensagens sucessivas.

    Solução por Enquadramento de Tamanho Fixo (Length-Prefixed Framing):
        Para restabelecer o limite exato de cada mensagem na camada de aplicação, este projeto
        adota um enquadramento composto por:
        
        [ 4 Bytes de Cabeçalho ] [ Payload JSON codificado em UTF-8 ]
        
        1. Cabeçalho (4 bytes): Um inteiro não assinado de 32 bits em ordem de rede
           (big-endian), representando exatamente a quantidade N de bytes do payload subsequente.
        2. Payload (N bytes): String JSON serializada em UTF-8 contendo os dados do pacote.

Garantias de Segurança do Protocolo:
    1. Confidencialidade: O texto em claro da mensagem (plaintext) JAMAIS é inserido nos pacotes TCP.
       Campos proibidos como 'message', 'plaintext', 'original' ou 'texto' são rejeitados ativamente.
    2. Chaves Privadas: O envio de chaves privadas é categoricamente bloqueado por filtros de inspeção.
    3. Tipagem Estrita: Apenas pacotes válidos e previstos pelo protocolo são aceitos.
"""

from __future__ import annotations

import json
import socket

# Tamanho fixo do cabeçalho de enquadramento em bytes (inteiro 32 bits = 4 bytes)
HEADER_SIZE = 4

# Tamanho máximo permitido para o payload JSON (1 MB), prevenindo ataques de esgotamento de memória (DoS)
MAX_PAYLOAD_BYTES = 1_000_000

# Tipos oficiais de pacotes suportados pelo protocolo da aplicação
PACKET_PUBLIC_KEY = "public_key"
PACKET_ENCRYPTED_MESSAGE = "encrypted_message"
PACKET_DISCONNECT = "disconnect"
PACKET_MESSAGE_ACK = "message_ack"

# Campos obrigatórios e permitidos no pacote de mensagem criptografada
ENCRYPTED_MESSAGE_REQUIRED_FIELDS = ("type", "sender", "recipient", "ciphertext")
ENCRYPTED_MESSAGE_ALLOWED_FIELDS = ENCRYPTED_MESSAGE_REQUIRED_FIELDS + ("message_id",)

# Campos do pacote de confirmação de descriptografia (ACK)
MESSAGE_ACK_FIELDS = ("type", "message_id", "sender", "recipient", "status")

# Lista de campos expressamente proibidos em pacotes de rede para impedir vazamento de texto em claro ou chaves
FORBIDDEN_PLAINTEXT_FIELDS = (
    "message",
    "plaintext",
    "original",
    "texto",
    "private_key",
)


class ProtocolError(Exception):
    """Exceção para erros de enquadramento de rede, desserialização JSON ou violação de segurança do protocolo."""


def recv_exact(connection: socket.socket, number_of_bytes: int) -> bytes:
    """Lê do socket TCP exatamente a quantidade especificada de bytes, acumulando fragmentos.

    Como a chamada nativa `recv()` não garante a devolução da quantidade total solicitada
    em uma única iteração, esta função efetua um loop de leitura incremental até que
    o buffer acumulado atinja rigorosamente 'number_of_bytes'.

    Args:
        connection: Objeto socket TCP ativo conectado ao peer.
        number_of_bytes: Número exato de bytes a serem lidos.

    Returns:
        bytes: Buffer contendo exatamente a quantidade de bytes requerida.

    Raises:
        ProtocolError: Se a quantidade for inválida, se a conexão for reiniciada
            ou se for encerrada prematuramente antes de completar o pacote.
    """
    if number_of_bytes < 0:
        raise ProtocolError("O número de bytes solicitado é inválido.")

    chunks = bytearray()
    while len(chunks) < number_of_bytes:
        remaining = number_of_bytes - len(chunks)
        try:
            piece = connection.recv(remaining)
        except ConnectionResetError as error:
            raise ProtocolError(
                "A conexão foi encerrada pelo outro lado durante a leitura."
            ) from error
        except OSError as error:
            raise ProtocolError(
                f"Falha de leitura no socket TCP: {error}"
            ) from error

        if piece == b"":
            if len(chunks) == 0:
                raise ProtocolError("A conexão TCP foi encerrada.")
            raise ProtocolError(
                "A conexão foi encerrada antes de receber o pacote completo."
            )
        chunks.extend(piece)

    return bytes(chunks)


def send_packet(connection: socket.socket, data: dict) -> None:
    """Serializa um dicionário em JSON UTF-8 e o transmite via TCP com cabeçalho de enquadramento de 4 bytes.

    Fluxo de Envio:
        1. Validação de formato e segurança do dicionário de dados.
        2. Serialização compacta em JSON UTF-8 (separadores sem espaços desnecessários).
        3. Verificação de conformidade com o limite máximo de payload (MAX_PAYLOAD_BYTES).
        4. Criação do cabeçalho de 4 bytes em big-endian com o tamanho exato do payload.
        5. Transmissão atômica do cabeçalho + payload utilizando `sendall()`.

    Args:
        connection: Socket TCP conectado ao destino.
        data: Dicionário contendo a estrutura de pacote da aplicação.

    Raises:
        ProtocolError: Em caso de falha de serialização JSON, estouro de limite
            ou encerramento do socket durante o envio.
    """
    if not isinstance(data, dict):
        raise ProtocolError("O pacote precisa ser um dicionário JSON.")

    _validate_outgoing_packet(data)

    try:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as error:
        raise ProtocolError(f"Não foi possível converter o pacote para JSON: {error}") from error

    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("O pacote JSON excede o tamanho máximo permitido.")

    header = len(payload).to_bytes(HEADER_SIZE, byteorder="big")
    try:
        connection.sendall(header + payload)
    except BrokenPipeError as error:
        raise ProtocolError("Não foi possível enviar: o outro lado encerrou a conexão.") from error
    except ConnectionResetError as error:
        raise ProtocolError("A conexão foi reiniciada durante o envio.") from error
    except OSError as error:
        raise ProtocolError(f"Falha de envio no socket TCP: {error}") from error


def receive_packet(connection: socket.socket) -> dict:
    """Recebe um pacote TCP completo reconstituído via enquadramento de 4 bytes e faz parse do JSON.

    Fluxo de Recepção:
        1. Leitura atômica dos primeiros 4 bytes (cabeçalho) via `recv_exact`.
        2. Conversão dos 4 bytes big-endian para inteiro, obtendo o tamanho exato do payload em bytes.
        3. Validação dos limites de tamanho do payload.
        4. Leitura atômica dos N bytes do payload via `recv_exact`.
        5. Decodificação UTF-8 e parsing do documento JSON para dicionário Python.
        6. Auditoria estrutural e de segurança do pacote recebido (`_validate_incoming_packet`).

    Args:
        connection: Socket TCP conectado.

    Returns:
        dict: Dicionário correspondente ao pacote JSON recebido.

    Raises:
        ProtocolError: Se o cabeçalho for inválido, se a conexão cair, se o UTF-8/JSON
            estiver malformado ou se violar regras de segurança.
    """
    header = recv_exact(connection, HEADER_SIZE)
    payload_size = int.from_bytes(header, byteorder="big")

    if payload_size == 0:
        raise ProtocolError("O cabeçalho TCP indicou um payload vazio.")
    if payload_size > MAX_PAYLOAD_BYTES:
        raise ProtocolError(
            f"O cabeçalho TCP indicou {payload_size} bytes, acima do limite permitido."
        )

    payload = recv_exact(connection, payload_size)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError(
            f"O payload TCP não está em UTF-8 válido: {error}"
        ) from error

    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ProtocolError(f"O payload TCP não é um JSON válido: {error}") from error

    if not isinstance(data, dict):
        raise ProtocolError("O JSON recebido precisa ser um objeto (dicionário).")

    _validate_incoming_packet(data)
    return data


def build_public_key_packet(sender: str, public_key_pem: str) -> dict:
    """Constrói o pacote JSON para troca de chave pública durante o handshake inicial.

    Garantia:
        A chave privada NUNCA deve ser passada a esta função nem transmitida pela rede.

    Args:
        sender: Identificador do remetente (ex.: 'Alice' ou 'Bob').
        public_key_pem: Conteúdo textual da chave pública em formato PEM.

    Returns:
        dict: Estrutura do pacote public_key pronto para envio.
    """
    return {
        "type": PACKET_PUBLIC_KEY,
        "sender": sender,
        "public_key": public_key_pem,
    }


def build_encrypted_message_packet(
    sender: str,
    recipient: str,
    ciphertext_base64: str,
    message_id: str | None = None,
) -> dict:
    """Constrói o pacote JSON contendo a mensagem criptografada.

    Segurança Arquitetural:
        O texto em claro NÃO é incluído neste pacote em hipótese alguma. O pacote
        transporta unicamente metadados de roteamento e o ciphertext resultante
        da operação RSA-4096 codificado em Base64.

    Args:
        sender: Nome do remetente ('Alice' ou 'Bob').
        recipient: Nome do destinatário pretendido.
        ciphertext_base64: Texto cifrado gerado por RSA-4096 codificado em Base64.
        message_id: Identificador único opcional da mensagem (UUID), utilizado para ACK.

    Returns:
        dict: Estrutura de pacote encrypted_message pronta para envio.
    """
    packet = {
        "type": PACKET_ENCRYPTED_MESSAGE,
        "sender": sender,
        "recipient": recipient,
        "ciphertext": ciphertext_base64,
    }
    if message_id:
        packet["message_id"] = message_id
    return packet


def build_message_ack_packet(
    sender: str,
    recipient: str,
    message_id: str,
    status: str = "decrypted",
) -> dict:
    """Constrói o pacote de confirmação de recebimento e descriptografia com sucesso (ACK).

    Este pacote é emitido pelo destinatário SOMENTE após a descriptografia real
    da mensagem com sua respectiva chave privada ter sido concluída sem erros.

    Args:
        sender: Identificador de quem descriptografou.
        recipient: Destinatário da confirmação (autor da mensagem original).
        message_id: Identificador da mensagem confirmada.
        status: Estado de confirmação (padrão 'decrypted').

    Returns:
        dict: Estrutura de pacote message_ack.
    """
    return {
        "type": PACKET_MESSAGE_ACK,
        "message_id": message_id,
        "sender": sender,
        "recipient": recipient,
        "status": status,
    }


def build_disconnect_packet(sender: str) -> dict:
    """Constrói o pacote de aviso gracioso de desconexão (encerramento com /sair).

    Args:
        sender: Nome do participante que está finalizando a sessão.

    Returns:
        dict: Estrutura de pacote disconnect.
    """
    return {
        "type": PACKET_DISCONNECT,
        "sender": sender,
    }


def _validate_outgoing_packet(data: dict) -> None:
    """Realiza a auditoria de segurança dos pacotes gerados antes do envio pela rede.

    Verifica se o pacote é válido e impede que chaves privadas vazem acidentalmente.
    """
    packet_type = data.get("type")
    if packet_type == PACKET_ENCRYPTED_MESSAGE:
        _assert_encrypted_message_shape(data)
    elif packet_type == PACKET_PUBLIC_KEY:
        if "PRIVATE KEY" in str(data.get("public_key", "")):
            raise ProtocolError(
                "Bloqueado: uma chave privada não pode ser enviada pela rede."
            )
    elif packet_type == PACKET_DISCONNECT:
        return
    elif packet_type == PACKET_MESSAGE_ACK:
        _assert_message_ack_shape(data)
    else:
        raise ProtocolError(f"Tipo de pacote de saída desconhecido: {packet_type!r}")


def _validate_incoming_packet(data: dict) -> None:
    """Audita rigorosamente os pacotes recebidos pela conexão TCP.

    Verificações de Segurança:
        1. O tipo de pacote deve pertencer ao conjunto de tipos autorizados.
        2. Proíbe qualquer campo que indique tráfego de texto em claro ou chave privada.
        3. Valida a conformidade dos campos esperados para cada tipo de pacote.
    """
    packet_type = data.get("type")
    if packet_type not in {
        PACKET_PUBLIC_KEY,
        PACKET_ENCRYPTED_MESSAGE,
        PACKET_DISCONNECT,
        PACKET_MESSAGE_ACK,
    }:
        raise ProtocolError(f"Tipo de pacote recebido desconhecido: {packet_type!r}")

    for forbidden in FORBIDDEN_PLAINTEXT_FIELDS:
        if forbidden in data:
            raise ProtocolError(
                f"O pacote TCP contém o campo proibido '{forbidden}'. "
                "A mensagem original não pode trafegar pela rede."
            )

    if packet_type == PACKET_ENCRYPTED_MESSAGE:
        _assert_encrypted_message_shape(data)
    elif packet_type == PACKET_MESSAGE_ACK:
        _assert_message_ack_shape(data)
    elif packet_type == PACKET_PUBLIC_KEY:
        pem = data.get("public_key")
        if not isinstance(pem, str) or pem.strip() == "":
            raise ProtocolError("O pacote public_key não trouxe uma chave pública.")
        if "PRIVATE KEY" in pem:
            raise ProtocolError(
                "Bloqueado: o peer tentou enviar uma chave privada."
            )


def _assert_encrypted_message_shape(data: dict) -> None:
    """Verifica se o pacote encrypted_message possui todos os campos obrigatórios e nenhum campo extra proibido."""
    extra = set(data.keys()) - set(ENCRYPTED_MESSAGE_ALLOWED_FIELDS)
    missing = set(ENCRYPTED_MESSAGE_REQUIRED_FIELDS) - set(data.keys())
    if missing:
        raise ProtocolError(
            "Pacote encrypted_message incompleto. "
            f"Campos ausentes: {', '.join(sorted(missing))}."
        )
    if extra:
        raise ProtocolError(
            "Pacote encrypted_message contém campos extras. "
            "Permitidos: type, sender, recipient, ciphertext e message_id. "
            f"Campos extras: {', '.join(sorted(extra))}."
        )
    if not isinstance(data["ciphertext"], str) or data["ciphertext"].strip() == "":
        raise ProtocolError("O campo ciphertext precisa ser uma string Base64.")
    message_id = data.get("message_id")
    if message_id is not None and (not isinstance(message_id, str) or not message_id.strip()):
        raise ProtocolError("O campo message_id precisa ser um texto não vazio.")


def _assert_message_ack_shape(data: dict) -> None:
    """Verifica a conformidade da estrutura do pacote de confirmação (message_ack)."""
    extra = set(data.keys()) - set(MESSAGE_ACK_FIELDS)
    missing = set(MESSAGE_ACK_FIELDS) - set(data.keys())
    if missing:
        raise ProtocolError(
            "Pacote message_ack incompleto. "
            f"Campos ausentes: {', '.join(sorted(missing))}."
        )
    if extra:
        raise ProtocolError(
            "Pacote message_ack contém campos extras. "
            f"Campos extras: {', '.join(sorted(extra))}."
        )
    if data.get("status") != "decrypted":
        raise ProtocolError("O ACK só pode confirmar status 'decrypted'.")
    if not isinstance(data.get("message_id"), str) or not data["message_id"].strip():
        raise ProtocolError("O ACK precisa identificar a mensagem.")

