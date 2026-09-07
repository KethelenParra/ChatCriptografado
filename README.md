# Chat Criptografado RSA-4096

Projeto desenvolvido para atividade acadêmica em dupla.

**Participantes**

- Kethelen — Alice
- Gabriel Mussatto — Bob

## Objetivo

Implementar comunicação remota cliente/servidor utilizando TCP Socket, com troca de informações criptografadas por RSA.

Cada computador gera o próprio par de chaves. A chave privada nunca sai da máquina de quem a gerou. Pela rede trafegam apenas a chave pública, o ciphertext e metadados necessários.

## Tecnologias

- Python
- TCP Socket
- RSA-4096
- OAEP
- SHA-256
- Base64
- React (futuramente)
- FastAPI (futuramente)
- WebSocket (futuramente)

## Arquitetura

| Papel | Pessoa | Programa |
| --- | --- | --- |
| Servidor TCP | Alice (Kethelen) | `python -m network.alice_server` |
| Cliente TCP | Bob (Gabriel Mussatto) | `python -m network.bob_client` |

Cada computador possui o próprio par RSA em `backend/keys/`:

- **Alice**
  - `private_key.pem` — privada da Alice (somente no PC dela)
  - `public_key.pem` — pública da Alice (pode ser enviada ao Bob)
- **Bob**
  - `private_key.pem` — privada do Bob (somente no PC dele)
  - `public_key.pem` — pública do Bob (pode ser enviada à Alice)

O diretório `backend/keys/` significa sempre **as chaves locais da máquina que está executando o programa**. Não se copia `private_key.pem` de um computador para outro.

### Fluxo das mensagens

**Alice → Bob**

1. Alice cifra com a **chave pública de Bob**.
2. Bob decifra com a **chave privada de Bob**.

**Bob → Alice**

1. Bob cifra com a **chave pública de Alice**.
2. Alice decifra com a **chave privada de Alice**.

As chaves privadas **nunca** são compartilhadas, nem mesmo em repositório Git privado.

## Estrutura do projeto

```text
ChatCriptografado/
├── backend/
│   ├── crypto/                 # geração, carga e cifra RSA
│   ├── network/                # protocolo TCP, servidor e cliente
│   ├── keys/                   # chaves LOCAIS (não versionadas)
│   ├── generate_bob_test_keys.py
│   ├── test_rsa.py
│   ├── test_alice_bob.py
│   └── requirements.txt
├── frontend/                   # React será implementado depois
├── .gitignore
└── README.md
```

A pasta `backend/test_keys/` existe apenas para simular Bob no mesmo computador da Alice. Ela **não** entra no Git e **não** são as chaves reais do Mussatto.

## Instalação

1. Clonar o repositório:

```powershell
git clone https://github.com/KethelenParra/ChatCriptografado.git
```

2. Entrar no backend:

```powershell
cd ChatCriptografado
cd backend
```

3. Criar e ativar o ambiente virtual.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Windows CMD:

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

4. Instalar as dependências:

```powershell
pip install -r requirements.txt
```

5. Gerar o par RSA-4096 **neste computador**:

```powershell
python .\crypto\key_manager.py
```

Cada participante deve executar esse comando **localmente**. Alice cria um par. Bob cria outro par, completamente diferente.

Nunca copiar `private_key.pem` de um computador para outro.

## Teste local (mesmo computador)

Útil enquanto Alice e Bob ainda não estão em máquinas distintas.

Antes, se ainda não existirem as chaves de simulação do Bob:

```powershell
python .\generate_bob_test_keys.py
```

**Terminal 1 — Alice (servidor)**

```powershell
python -m network.alice_server
```

Usa, por padrão, `127.0.0.1:5000` e `backend/keys/`.

**Terminal 2 — Bob simulado**

```powershell
python -m network.bob_client --keys-dir test_keys/bob
```

O argumento `--keys-dir test_keys/bob` faz o cliente usar o par de **teste**, para não misturar com as chaves reais da Alice.

Para encerrar a conversa, digite `/sair`.

## Execução real (dois computadores)

Ainda sem IP definitivo. Posteriormente os computadores serão ligados por uma rede privada.

**Alice (servidor)**

```powershell
python -m network.alice_server --host 0.0.0.0 --port 5000
```

`0.0.0.0` faz o servidor aceitar conexões da rede, não apenas de `127.0.0.1`.

**Bob (cliente), no computador do Mussatto**

```powershell
python -m network.bob_client --host <IP_DA_ALICE> --port 5000
```

No PC do Bob, `--keys-dir` não precisa ser informado: o padrão é `backend/keys/`, onde estarão as chaves geradas por ele.

## Argumentos

Tanto o servidor quanto o cliente aceitam:

| Argumento | Padrão | Função |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Alice: endereço de escuta. Bob: endereço da Alice. |
| `--port` | `5000` | Porta TCP. |
| `--keys-dir` | `keys` | Diretório das chaves locais, relativo a `backend/`. |

## Segurança

- **RSA** é criptografia assimétrica: usa um par (pública + privada).
- **RSA-4096** usa módulo de 4096 bits. O bloco cifrado tem 4096 bits = **512 bytes**.
- **OAEP** é o padding seguro da operação RSA. Inclui aleatoriedade: a mesma mensagem gera ciphertext diferente a cada envio.
- **SHA-256** é o hash usado dentro do OAEP (e no MGF1).
- A **chave pública** pode ser compartilhada com o outro participante.
- A **chave privada** permanece somente no computador de quem a gerou.
- **Base64 não é criptografia.** Serve só para representar os bytes RSA em texto, para o JSON e, no futuro, para a interface.
- A mensagem original **não trafega** no pacote TCP. O JSON `encrypted_message` contém apenas `type`, `sender`, `recipient` e `ciphertext`.
- Com RSA-4096 + OAEP/SHA-256, o texto em claro tem limite aproximado de **446 bytes UTF-8** por mensagem (acentos e emojis contam como mais de um byte).

Em sistemas reais de grande escala costuma-se usar **criptografia híbrida** (RSA para trocar uma chave simétrica, AES para a mensagem). Este trabalho cifra diretamente com RSA para atender e demonstrar o requisito acadêmico.

## Testes automatizados

A partir de `backend/`, com o ambiente virtual ativo:

```powershell
python .\test_rsa.py
python .\test_alice_bob.py
```

O segundo teste usa `backend/keys/` (Alice) e `backend/test_keys/bob/` (Bob simulado). As chaves de teste não são as chaves reais do Mussatto.
