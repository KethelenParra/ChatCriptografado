# Chat Criptografado RSA-4096

Repositório acadêmico contendo a implementação, testes e documentação de um sistema de comunicação remota segura ponto a ponto via **TCP Socket**, utilizando criptografia assimétrica **RSA-4096** com preenchimento seguro **OAEP** e função hash **SHA-256**.

---

## 1. Descrição do Projeto

Este projeto consiste em uma atividade acadêmica prática para a disciplina de **Segurança da Informação** (8º Período). O objetivo é demonstrar na prática os conceitos fundamentais de criptografia de chave pública (assimétrica), integridade de dados, protocolo de transporte com enquadramento (*framing* TCP), preservação da confidencialidade e isolamento estrito de segredos criptográficos entre dois participantes remotos comunicando-se por meio de redes distintas interligadas via **Tailscale**.

---

## 2. Participantes

O sistema modela formalmente o cenário clássico de comunicação entre **Alice** e **Bob**:

- **Alice**:
  - **Integrante**: Kethelen Parra
  - **Papel de Rede**: Servidor TCP (*Listener*)
  - **Comportamento**: Aguarda conexão remota, realiza o handshake de chaves públicas, cifra mensagens para Bob e decifra mensagens recebidas com sua chave privada local.
- **Bob**:
  - **Integrante**: Gabriel Mussatto
  - **Papel de Rede**: Cliente TCP (*Connector*)
  - **Comportamento**: Estabelece conexão ativa com a Alice, realiza o handshake de chaves públicas, cifra mensagens para Alice e decifra mensagens recebidas com sua chave privada local.

---

## 3. Objetivo

O objetivo primordial do projeto é viabilizar um chat em tempo real onde mensagens textuais trafeguem por um canal de transporte público/inseguro com garantia matemática de **confidencialidade**:
1. Nenhum intermediário na rede (provedor de internet, roteadores intermediários ou invasores com analisadores de pacotes como Wireshark) consegue ler o conteúdo original das mensagens.
2. Cada participante é o único capaz de decifrar o conteúdo a ele endereçado, pois apenas ele possui a chave privada correspondente.
3. Demonstração educacional clara de como a criptografia assimétrica atua sobre cada mensagem transmitida, exibindo os dados originais, o ciphertext de 512 bytes em Base64 e o processo de descriptografia.

---

## 4. Tecnologias Utilizadas

- **Python 3.10+**: Linguagem principal do ecossistema backend e controle de sockets.
- **TCP Socket (módulo `socket`)**: Protocolo de transporte confiável e orientado a fluxo de bytes para a comunicação remota Alice ↔ Bob.
- **RSA-4096 (módulo `cryptography.hazmat`)**: Criptografia assimétrica de alta segurança com módulo de 4096 bits ($n = p \cdot q$).
- **OAEP (Optimal Asymmetric Encryption Padding)**: Esquema de preenchimento probabilístico seguro contra ataques de texto em claro escolhido (IND-CCA2).
- **SHA-256 (Secure Hash Algorithm 256 bits)**: Algoritmo de hash criptográfico utilizado como função de resumo no OAEP e no gerador de máscara MGF1.
- **Base64 (RFC 4648)**: Esquema de codificação textual utilizado exclusivamente para transporte e exibição em JSON dos 512 bytes binários do ciphertext.
- **JSON (JavaScript Object Notation)**: Formato padronizado de representação e intercâmbio de pacotes de dados.
- **Tailscale (WireGuard VPN Mesh)**: Infraestrutura de rede virtual segura para estabelecer conectividade direta IP ponto a ponto entre computadores localizados em redes residenciais distintas com NAT traversal automático.
- **FastAPI / Uvicorn** *(opcional)*: Servidor de API HTTP e WebSocket local para ponte com a interface visual.
- **React + Vite** *(opcional)*: Interface gráfica interativa para inspeção visual detalhada das mensagens e blocos criptografados.

---

## 5. Arquitetura

O sistema opera no modelo **Ponto a Ponto (Peer-to-Peer)** sobre a camada de transporte TCP.

### 5.1. Fluxo de Comunicação Remota (Terminal TCP)

```text
       [ PC da Alice ]                                    [ PC do Bob ]
     (Servidor TCP: 5000)                             (Cliente TCP: 5000)
    +--------------------+                           +--------------------+
    |  Chave Privada     |                           |  Chave Privada     |
    |  (EXCLUSIVA Alice) |                           |  (EXCLUSIVA Bob)   |
    |  private_key.pem   |                           |  private_key.pem   |
    +--------------------+                           +--------------------+
              |                                                |
    +--------------------+                           +--------------------+
    |  Chave Pública     |   --- Chave Pública Alice --->    |  Chave Pública     |
    |  public_key.pem    |   <--- Chave Pública Bob ---      |  public_key.pem    |
    +--------------------+                           +--------------------+
              |                                                |
              | ====== Canal Remoto TCP (via Tailscale) ===== |
              |                                                |
              | --- Pacote JSON (Ciphertext RSA-4096) ---->   |
              |     [Cifrado com Chave Pública do Bob]        |
              |     [Decifrado com Chave Privada do Bob]       |
              |                                                |
              | <--- Pacote JSON (Ciphertext RSA-4096) -----  |
              |     [Cifrado com Chave Pública da Alice]      |
              |     [Decifrado com Chave Privada da Alice]     |
              |                                                |
              | <==== Confirmação ACK de Decifragem (TCP) ===  |
              v                                                v
```

### 5.2. Arquitetura com Interface Gráfica Local (React + FastAPI)

Quando utilizada a interface gráfica, o WebSocket opera **estritamente em localhost** (`127.0.0.1`), atuando apenas como ponte entre a interface web no navegador e o processo Python local:

```text
[Navegador Alice] <--(WebSocket Local)--> [FastAPI Alice] <--(TCP Socket Remoto via Tailscale)--> [FastAPI Bob] <--(WebSocket Local)--> [Navegador Bob]
```

> [!NOTE]
> O WebSocket **não substitui** o TCP. Toda a comunicação entre as duas casas trafega exclusivamente via TCP Socket + RSA-4096.

---

## 6. Funcionamento da Criptografia

### 6.1. Regra Fundamental da Criptografia Assimétrica

1. **Sentido Alice → Bob**:
   - **Cifragem**: Alice utiliza a **chave pública do Bob**.
   - **Decifragem**: Apenas Bob consegue decifrar, utilizando sua **chave privada local**.
2. **Sentido Bob → Alice**:
   - **Cifragem**: Bob utiliza a **chave pública da Alice**.
   - **Decifragem**: Apenas Alice consegue decifrar, utilizando sua **chave privada local**.

### 6.2. RSA-4096 + OAEP + SHA-256

- **Módulo RSA de 4096 bits**:
  O produto dos dois primos grandes $n = p \cdot q$ resulta em um número de 4096 bits.
  Como $4096 \text{ bits} / 8 = 512 \text{ bytes}$, o resultado de qualquer operação de cifragem RSA-4096 é **rigorosamente um bloco de 512 bytes**.
- **Padding OAEP (Optimal Asymmetric Encryption Padding)**:
  O RSA básico (*textbook RSA*) é determinístico ($c = m^e \pmod n$), o que significa que cifrar o mesmo texto geraria sempre o mesmo ciphertext. O OAEP soluciona essa fraqueza aplicando uma rede Feistel com semente aleatória e função geradora de máscaras (MGF1 com SHA-256).
- **Natureza Probabilística**:
  Mesmo que Alice envie dez vezes a palavra `"Oi"`, o algoritmo OAEP adicionará um vetor aleatório diferente a cada execução, resultando em **dez ciphertexts de 512 bytes completamente distintos e imprevisíveis**.

---

## 7. Segurança das Chaves

A segurança do projeto baseia-se no princípio de isolamento absoluto:

1. **Chaves Privadas (`private_key.pem`)**:
   - Permanecem **EXCLUSIVAMENTE** na máquina onde foram geradas.
   - **NUNCA** trafegam pela rede TCP.
   - **NUNCA** são compartilhadas com o parceiro, enviadas por e-mail ou impressas no terminal.
   - **NUNCA** entram no controle de versão Git.
2. **Chaves Públicas (`public_key.pem`)**:
   - Projetadas para distribuição pública.
   - São trocadas automaticamente pelo canal TCP durante o handshake de inicialização.
   - O interlocutor mantém a chave pública recebida **apenas em memória** durante a sessão de conexão.
3. **Proteção no `.gitignore`**:
   Tanto a raiz quanto a pasta `backend/` contêm regras ativas no `.gitignore` que impedem o rastreamento acidental de arquivos de chave:
   ```gitignore
   *.pem
   backend/keys/*.pem
   backend/test_keys/
   ```

---

## 8. Protocolo de Comunicação

### 8.1. Semântica do TCP e Enquadramento (*Framing*)

O TCP é um protocolo orientado a **stream de bytes** (RFC 793). Ele garante entrega ordenada e confiável, mas não delimita o final de uma mensagem e o início de outra. Um comando `recv()` pode retornar meio pacote ou múltiplos pacotes aglutinados.

Para garantir que a aplicação reconstrua com precisão cada mensagem JSON, implementou-se o seguinte padrão de enquadramento em [protocol.py](file:///d:/Faculdade/8%20Periodo/Seguran%C3%A7a/ChatCriptografado/backend/network/protocol.py):

```text
+-------------------------+----------------------------------------------+
| Cabeçalho (4 bytes)     | Payload (N bytes)                            |
| Tamanho N em big-endian | String JSON serializada em UTF-8             |
+-------------------------+----------------------------------------------+
```

A função `recv_exact(connection, N)` acumula bytes em buffer até atingir exatamente o tamanho especificado pelo cabeçalho.

### 8.2. Tipos de Pacotes Existentes no Código

1. **`public_key`** (Troca de chave pública no handshake inicial):
   ```json
   {
     "type": "public_key",
     "sender": "Alice",
     "public_key": "-----BEGIN PUBLIC KEY-----\n..."
   }
   ```
2. **`encrypted_message`** (Transporte de mensagem cifrada):
   ```json
   {
     "type": "encrypted_message",
     "sender": "Alice",
     "recipient": "Bob",
     "ciphertext": "k9xP...==",
     "message_id": "uuid-opcional"
   }
   ```
   > [!IMPORTANT]
   > O pacote TCP transporta unicamente metadados e o `ciphertext` em Base64. O texto original em claro **nunca é enviado pela rede**.
3. **`message_ack`** (Confirmação de recebimento e decifragem real):
   ```json
   {
     "type": "message_ack",
     "message_id": "uuid-opcional",
     "sender": "Bob",
     "recipient": "Alice",
     "status": "decrypted"
   }
   ```
4. **`disconnect`** (Encerramento gracioso com `/sair`):
   ```json
   {
     "type": "disconnect",
     "sender": "Alice"
   }
   ```

---

## 9. Estrutura do Projeto

```text
ChatCriptografado/
├── .gitignore                      # Regras de segurança globais (ignora .pem, .venv, etc.)
├── LICENSE                         # Licença MIT do projeto
├── MANUAL_EXECUCAO.md              # Manual passo a passo para execução a partir de máquina limpa
├── README.md                       # Documentação acadêmica principal
├── backend/
│   ├── .gitignore                  # Proteção local de chaves e ambientes
│   ├── requirements.txt            # Dependências Python (cryptography, fastapi, uvicorn)
│   ├── run_gui.py                  # Launcher integrado backend + interface gráfica
│   ├── generate_bob_test_keys.py   # Utilitário para gerar par simulado do Bob em testes locais
│   ├── test_rsa.py                 # Teste unitário didático do RSA local
│   ├── test_alice_bob.py           # Teste de comunicação assimétrica bidirecional
│   ├── test_chat_runtime.py        # Teste do motor de eventos sem terminal interativo
│   ├── api/
│   │   ├── app.py                  # Instância FastAPI, rotas HTTP e ciclo de vida
│   │   └── websocket_manager.py    # Gerenciador de conexões WebSocket locais
│   ├── crypto/
│   │   ├── key_manager.py          # Geração, armazenamento e validação das chaves RSA locais
│   │   └── rsa_service.py          # Cifragem, decifragem RSA-4096 OAEP/SHA-256 e Base64
│   ├── network/
│   │   ├── __init__.py             # Resolução de diretórios de chaves
│   │   ├── protocol.py             # Enquadramento TCP (4 bytes) e validação de pacotes
│   │   ├── alice_server.py         # Servidor TCP de terminal da Alice
│   │   └── bob_client.py           # Cliente TCP de terminal do Bob
│   ├── services/
│   │   └── chat_runtime.py         # Motor de sessão TCP, threads de I/O e fila de eventos
│   └── keys/                       # Chaves locais da máquina (NÃO versionadas no Git)
│       ├── private_key.pem         # Chave privada local (gerada pelo key_manager)
│       └── public_key.pem          # Chave pública local (gerada pelo key_manager)
└── frontend/                       # Interface opcional em React + Vite
    ├── package.json
    ├── vite.config.js
    └── src/
```

---

## 10. Instalação

### 10.1. Pré-requisitos
- Python 3.10 ou superior instalado.
- Gerenciador de pacotes `pip`.
- Node.js 18+ (necessário apenas se for executar a interface gráfica opcional).

### 10.2. Clonagem e Configuração do Ambiente Virtual

1. Clone o repositório:
   ```bash
   git clone https://github.com/KethelenParra/ChatCriptografado.git
   cd ChatCriptografado/backend
   ```

2. Crie o ambiente virtual `.venv`:
   ```bash
   python -m venv .venv
   ```

3. Ative o ambiente virtual:
   - **Windows PowerShell**:
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```
   - **Windows Prompt de Comando (CMD)**:
     ```cmd
     .venv\Scripts\activate.bat
     ```
   - **Linux / macOS**:
     ```bash
     source .venv/bin/activate
     ```

4. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

---

## 11. Geração das Chaves

Cada participante deve gerar **seu próprio par de chaves RSA-4096 localmente em seu respectivo computador**:

```powershell
python .\crypto\key_manager.py
```

O comando criará automaticamente a pasta `backend/keys/` com:
- `private_key.pem`: Chave privada (protegida localmente).
- `public_key.pem`: Chave pública (compartilhável).

> [!CAUTION]
> Cada participante gera o seu próprio par independente. Alice e Bob **NUNCA** devem copiar ou enviar seus arquivos `private_key.pem` um para o outro.

---

## 12. Teste Local no Mesmo Computador

Para testar o fluxo de rede em uma única máquina, utilize o script auxiliar para criar o par de chaves de simulação do Bob:

1. Gere as chaves de teste para simular o Bob:
   ```powershell
   python .\generate_bob_test_keys.py
   ```
   *(Isso criará as chaves do Bob em `backend/test_keys/bob/`, sem alterar as chaves da Alice em `backend/keys/`)*.

2. **Terminal 1 — Inicie a Alice (Servidor)**:
   ```powershell
   python -m network.alice_server --host 127.0.0.1 --port 5000
   ```

3. **Terminal 2 — Inicie o Bob simulado (Cliente)**:
   ```powershell
   python -m network.bob_client --host 127.0.0.1 --port 5000 --keys-dir test_keys/bob
   ```

4. Digite mensagens alternadas no terminal e observe a cifragem e a descriptografia em tempo real. Digite `/sair` para finalizar.

---

## 13. Execução entre Dois Computadores (Tailscale)

Para conectar dois computadores físicos em redes domésticas diferentes, utiliza-se a VPN em malha **Tailscale**:

1. Ambos os participantes instalam o [Tailscale](https://tailscale.com/) e efetuam login na mesma organização (*tailnet*).
2. **Descobrir o IP Tailscale da Alice**:
   No computador da Alice, execute no terminal:
   ```bash
   tailscale ip -4
   ```
   *(Ou consulte o IP `100.x.y.z` diretamente no aplicativo Tailscale).*
3. **Regra de Firewall**:
   Certifique-se de que a porta TCP 5000 não está bloqueada pelo Firewall do Windows para a interface de rede do Tailscale.

---

## 14. Comandos de Execução

### 14.1. Modo Terminal (Padrão Acadêmico Direto)

- **No computador da Alice (Servidor TCP)**:
  Escuta em todas as interfaces de rede na porta 5000:
  ```powershell
  python -m network.alice_server --host 0.0.0.0 --port 5000
  ```

- **No computador do Bob (Cliente TCP)**:
  Conecta ao endereço IP Tailscale da Alice:
  ```powershell
  python -m network.bob_client --host <IP_TAILSCALE_ALICE> --port 5000
  ```

### 14.2. Modo Interface Gráfica (Opcional com React + FastAPI)

- **No computador da Alice**:
  ```powershell
  # Terminal 1 (Backend FastAPI)
  python .\run_gui.py --role alice --tcp-host 0.0.0.0 --tcp-port 5000

  # Terminal 2 (Frontend React)
  cd ..\frontend
  npm install
  npm run dev
  ```
  Acesse `http://localhost:5173` e clique em **Iniciar Servidor**.

- **No computador do Bob**:
  ```powershell
  # Terminal 1 (Backend FastAPI)
  python .\run_gui.py --role bob --peer-host <IP_TAILSCALE_ALICE> --tcp-port 5000

  # Terminal 2 (Frontend React)
  cd ..\frontend
  npm install
  npm run dev
  ```
  Acesse `http://localhost:5173` e clique em **Conectar à Alice**.

---

## 15. Como Utilizar o Chat

1. Inicie o servidor da Alice e certifique-se de que o banner `"Servidor aguardando conexão..."` está ativo.
2. Inicie o cliente do Bob apontando para o IP da Alice.
3. Observe no log dos terminais a troca automática de chaves públicas:
   - Alice envia sua chave pública para Bob e recebe a dele.
   - Bob recebe a chave pública de Alice e envia a sua.
4. Digite a mensagem no terminal do remetente e pressione `Enter`.
5. Observe no console:
   - O texto original.
   - O ciphertext de 512 bytes codificado em Base64.
   - A confirmação de envio via TCP.
   - O destinatário recebendo o bloco criptografado e decifrando-o com sua própria chave privada.
6. Para finalizar a conversa a qualquer instante, digite `/sair`. O socket será encerrado graciosamente em ambos os terminais.

---

## 16. Limitações e Fundamentação Teórica

### 16.1. Limite de Tamanho da Mensagem Original

O RSA opera sobre blocos matemáticos limitados pelo tamanho do módulo $n$. Com preenchimento seguro **OAEP** e função de hash **SHA-256**, a capacidade útil máxima para o texto em claro é definida pela fórmula formal da RFC 8017:

$$\text{Tamanho Máximo} = k - 2 \cdot hLen - 2$$

Onde:
- $k$: tamanho do módulo em bytes ($4096 \text{ bits} / 8 = 512 \text{ bytes}$).
- $hLen$: tamanho da saída da função hash SHA-256 ($32 \text{ bytes}$).
- Constante do preenchimento OAEP: $2 \text{ bytes}$.

Portanto:
$$\text{Tamanho Máximo} = 512 - (2 \cdot 32) - 2 = 512 - 64 - 2 = 446 \text{ bytes UTF-8}$$

Caso uma mensagem exceda 446 bytes UTF-8, o sistema bloqueia o envio e lança uma exceção `RsaServiceError`.

### 16.2. Criptografia Assimétrica Pura vs. Criptografia Híbrida

- **Abordagem Adotada no Projeto**: Utiliza criptografia assimétrica RSA direta sobre cada mensagem para cumprir estritamente o escopo didático da atividade de segurança.
- **Prática em Sistemas Comerciais (ex.: TLS, SSH, PGP)**: Em sistemas reais de larga escala, adota-se a **criptografia híbrida**: o algoritmo assimétrico (como RSA ou ECDH) é utilizado exclusivamente para autenticação e troca segura de uma chave de sessão simétrica efêmera, e as mensagens subsequentes são cifradas com um algoritmo simétrico de alta performance (como AES-GCM ou ChaCha20-Poly1305), eliminando limitações de tamanho de bloco.

---

## 17. Testes Realizados

O projeto inclui três suítes de testes automatizados independentes:

1. **Teste Criptográfico Unitário Local (`test_rsa.py`)**:
   Valida o ciclo completo de cifragem e decifragem RSA-4096 com OAEP/SHA-256 e Base64 em ambiente local:
   ```powershell
   python .\test_rsa.py
   ```
2. **Teste de Comunicação Bidirecional Cruzada (`test_alice_bob.py`)**:
   Valida a troca cruzada entre dois pares de chaves distintos (Alice e Bob simulado) e inclui um teste negativo comprovando que a chave privada de Alice **não** consegue abrir mensagens cifradas para a chave pública de Bob:
   ```powershell
   python .\test_alice_bob.py
   ```
3. **Teste do Motor de Execução sem Interface (`test_chat_runtime.py`)**:
   Testa a abertura dinâmica de portas, handshake automatizado de chaves públicas, confirmações de decifragem (`message_ack`) e transmissão segura em background:
   ```powershell
   python .\test_chat_runtime.py
   ```

---

## 18. Considerações de Segurança

- **Confidencialidade Ponto a Ponto**: Todo o tráfego que percorre o socket TCP está criptografado com RSA-4096 bits.
- **Validação de Chaves no Handshake**: O sistema rejeita ativamente chaves recebidas que não sejam do algoritmo RSA ou que tenham dimensão diferente de 4096 bits.
- **Prevenção Ativa contra Vazamento de Segredos**:
  - Filtros no protocolo inspecionam pacotes enviados e bloqueiam qualquer envio que contenha termos de chaves privadas (`PRIVATE KEY`).
  - O protocolo proíbe a inclusão de campos de texto em claro nos pacotes de rede.
- **Proteção de Integridade**: O preenchimento OAEP com SHA-256 garante integridade do ciphertext; mensagens adulteradas na rede falham matematicamente na decifragem.
- **Auditoria de Repositório**: Regras estritas no `.gitignore` impedem a inclusão acidental de chaves criptográficas `.pem`, variáveis `.env` ou ambientes virtuais no controle de versão.

---

## 19. Licença

Este projeto é distribuído sob os termos da licença **MIT**. Consulte o arquivo [LICENSE](file:///d:/Faculdade/8%20Periodo/Seguran%C3%A7a/ChatCriptografado/LICENSE) para mais informações.
