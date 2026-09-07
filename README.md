# Chat Criptografado RSA-4096

Projeto desenvolvido para atividade acadêmica em dupla.

**Participantes**

- Kethelen — Alice
- Gabriel Mussatto — Bob

## Objetivo

Implementar comunicação remota cliente/servidor utilizando TCP Socket, com troca de informações criptografadas por RSA, e uma interface gráfica local em React.

Cada computador gera o próprio par de chaves. A chave privada nunca sai da máquina de quem a gerou. Pela rede trafegam apenas a chave pública, o ciphertext e metadados necessários.

## Tecnologias

- Python
- TCP Socket (comunicação remota Alice ↔ Bob)
- RSA-4096
- OAEP
- SHA-256
- Base64
- FastAPI (API local)
- WebSocket (ponte local React ↔ Python)
- React + Vite (interface)

## Arquitetura

O WebSocket **não substitui** o TCP. Ele só liga o navegador ao Python **deste computador**. A conversa entre as casas continua no TCP + RSA.

```text
React
  ↓ WebSocket local
FastAPI
  ↓
TCP Socket + RSA-4096
  ↓
Tailscale
  ↓
TCP Socket + RSA-4096
  ↓
FastAPI
  ↓ WebSocket local
React
```

| Papel | Pessoa | Programa |
| --- | --- | --- |
| Servidor TCP | Alice (Kethelen) | `python .\run_gui.py --role alice` ou `python -m network.alice_server` |
| Cliente TCP | Bob (Gabriel Mussatto) | `python .\run_gui.py --role bob --peer-host <IP>` ou `python -m network.bob_client` |

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
3. Bob envia `message_ack` somente se a descriptografia funcionar.

**Bob → Alice**

1. Bob cifra com a **chave pública de Alice**.
2. Alice decifra com a **chave privada de Alice**.
3. Alice envia `message_ack` após descriptografar com sucesso.

As chaves privadas **nunca** são compartilhadas, nem mesmo em repositório Git privado.

## Estrutura do projeto

```text
ChatCriptografado/
├── backend/
│   ├── api/                    # FastAPI + WebSocket local
│   ├── services/               # ChatRuntime (TCP/RSA sem input())
│   ├── crypto/                 # geração, carga e cifra RSA
│   ├── network/                # protocolo TCP, servidor e cliente de terminal
│   ├── keys/                   # chaves LOCAIS (não versionadas)
│   ├── run_gui.py
│   ├── requirements.txt
│   └── ...
├── frontend/                   # React + Vite
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

6. Frontend (em outro terminal):

```powershell
cd ChatCriptografado\frontend
npm install
```

Opcional: copie `frontend/.env.example` para `frontend/.env`. Os valores padrão já apontam para `127.0.0.1:8000`.

## Interface gráfica

O FastAPI sobe em `127.0.0.1:8000`. O React sobe em `http://localhost:5173`. A conexão TCP **não** inicia sozinha: use os botões da interface.

### Alice (Kethelen)

Backend:

```powershell
cd ChatCriptografado\backend
.\.venv\Scripts\Activate.ps1
python .\run_gui.py --role alice --tcp-host 0.0.0.0 --tcp-port 5000
```

Frontend:

```powershell
cd ChatCriptografado\frontend
npm run dev
```

Abrir `http://localhost:5173` e clicar em **Iniciar servidor**.

### Bob (Gabriel Mussatto)

Backend (troque `<IP_TAILSCALE_ALICE>` pelo IP atual da Alice na rede privada):

```powershell
cd ChatCriptografado\backend
.\.venv\Scripts\Activate.ps1
python .\run_gui.py --role bob --peer-host <IP_TAILSCALE_ALICE> --tcp-port 5000
```

Frontend:

```powershell
cd ChatCriptografado\frontend
npm run dev
```

Abrir `http://localhost:5173` e clicar em **Conectar à Alice**.

### Painel criptográfico

Cada mensagem tem o botão **Ver mensagem criptografada**. O painel mostra dados **reais** daquela mensagem:

- texto local (somente nesta máquina)
- ciphertext Base64
- RSA-4096, OAEP, SHA-256
- tamanho em bytes UTF-8 e tamanho do ciphertext (512)
- chave pública usada na cifra
- confirmação de que o plaintext **não** foi no pacote TCP
- ACK: “descriptografada pelo destinatário” só depois da descriptografia real

A chave privada nunca é exibida. Base64 não é criptografia.

## Teste local no terminal (mesmo computador)

Antes, se ainda não existirem as chaves de simulação do Bob:

```powershell
python .\generate_bob_test_keys.py
```

**Terminal 1 — Alice (servidor)**

```powershell
python -m network.alice_server
```

**Terminal 2 — Bob simulado**

```powershell
python -m network.bob_client --keys-dir test_keys/bob
```

Para encerrar a conversa, digite `/sair`.

## Argumentos do terminal TCP

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
- **Base64 não é criptografia.** Serve só para representar os bytes RSA em texto, no JSON e no painel da interface.
- A mensagem original **não trafega** no pacote TCP. O JSON `encrypted_message` contém `type`, `sender`, `recipient`, `ciphertext` e, na interface, `message_id`.
- O `message_ack` confirma descriptografia real. Não leva plaintext.
- Com RSA-4096 + OAEP/SHA-256, o texto em claro tem limite aproximado de **446 bytes UTF-8** por mensagem.

Em sistemas reais de grande escala costuma-se usar **criptografia híbrida** (RSA para trocar uma chave simétrica, AES para a mensagem). Este trabalho cifra diretamente com RSA para atender e demonstrar o requisito acadêmico.

## Testes automatizados

A partir de `backend/`, com o ambiente virtual ativo:

```powershell
python .\test_rsa.py
python .\test_alice_bob.py
python .\test_chat_runtime.py
```

O segundo e o terceiro testes usam `backend/keys/` (Alice) e `backend/test_keys/bob/` (Bob simulado). As chaves de teste não são as chaves reais do Mussatto.
