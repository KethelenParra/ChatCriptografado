# Manual de Execução — Chat Criptografado RSA-4096

Este manual fornece um guia completo, passo a passo, voltado para professores, avaliadores e estudantes que desejem reproduzir, configurar e executar o projeto **ChatCriptografado** a partir de um computador recém-formatado ou ambiente limpo.

---

## Sumário

1. [Pré-requisitos](#1-pré-requisitos)
2. [Clonar o Repositório](#2-clonar-o-repositório)
3. [Entrar na Pasta Backend](#3-entrar-na-pasta-backend)
4. [Criar o Ambiente Virtual](#4-criar-o-ambiente-virtual)
5. [Ativar o Ambiente Virtual](#5-ativar-o-ambiente-virtual)
6. [Instalar Dependências](#6-instalar-dependências)
7. [Gerar as Chaves RSA-4096](#7-gerar-as-chaves-rsa-4096)
8. [Verificar a Proteção das Chaves](#8-verificar-a-proteção-das-chaves)
9. [Configurar o Tailscale](#9-configurar-o-tailscale)
10. [Colocar Alice e Bob na Mesma Tailnet](#10-colocar-alice-e-bob-na-mesma-tailnet)
11. [Descobrir o IP Tailscale da Alice](#11-descobrir-o-ip-tailscale-da-alice)
12. [Iniciar o Servidor da Alice](#12-iniciar-o-servidor-da-alice)
13. [Iniciar o Cliente do Bob](#13-iniciar-o-cliente-do-bob)
14. [Enviar Mensagens Criptografadas](#14-enviar-mensagens-criptografadas)
15. [Encerrar a Conexão com /sair](#15-encerrar-a-conexão-com-sair)
16. [Solução de Problemas Comuns (Troubleshooting)](#16-solução-de-problemas-comuns-troubleshooting)

---

## 1. Pré-requisitos

Antes de iniciar, certifique-se de que a máquina possui instalados:

- **Python 3.10 ou superior**:
  Verifique no terminal:
  ```bash
  python --version
  ```
  *(Caso não possua, baixe em [python.org](https://www.python.org/downloads/) e marque a opção **"Add Python to PATH"** durante a instalação).*
- **Git**:
  Verifique com:
  ```bash
  git --version
  ```
- **Tailscale** *(Apenas para teste entre dois computadores físicos distintos)*:
  Download gratuito em [tailscale.com/download](https://tailscale.com/download).
- *(Opcional)* **Node.js 18+ e npm**:
  Necessário exclusivamente se for executar a interface gráfica web em React localizada na pasta `frontend/`.

---

## 2. Clonar o Repositório

Abra um terminal (PowerShell, CMD ou Bash) e clone o projeto:

```bash
git clone https://github.com/KethelenParra/ChatCriptografado.git
```

---

## 3. Entrar na Pasta Backend

Toda a lógica criptográfica, serviços de rede e scripts de execução situam-se no diretório `backend`:

```bash
cd ChatCriptografado/backend
```

---

## 4. Criar o Ambiente Virtual

Crie um ambiente virtual Python isolado chamado `.venv` para evitar conflitos com pacotes globais do sistema operacional:

```bash
python -m venv .venv
```

---

## 5. Ativar o Ambiente Virtual

A ativação depende do terminal e sistema operacional utilizado:

### No Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```

> [!TIP]
> Caso o PowerShell bloqueie a execução de scripts com erro de *ExecutionPolicy*, execute antes no mesmo terminal:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .\.venv\Scripts\Activate.ps1
> ```

### No Windows Prompt de Comando (CMD):
```cmd
.venv\Scripts\activate.bat
```

### No Linux / macOS:
```bash
source .venv/bin/activate
```

*(Após a ativação, o indicador `(.venv)` aparecerá no início da linha de comando).*

---

## 6. Instalar Dependências

Com o ambiente virtual ativado, instale as dependências listadas no `requirements.txt`:

```bash
pip install -r requirements.txt
```

As bibliotecas instaladas serão:
- `cryptography`: biblioteca de padrões criptográficos (primitivas RSA, OAEP, SHA-256 e serialização PEM).
- `fastapi` e `uvicorn`: servidores locais utilizados opcionalmente pela interface gráfica.

---

## 7. Gerar as Chaves RSA-4096

Cada participante deve gerar seu próprio par criptográfico **localmente em sua máquina**.

Execute o gerenciador de chaves:

### No Windows:
```powershell
python .\crypto\key_manager.py
```

### No Linux / macOS:
```bash
python crypto/key_manager.py
```

### O que este comando faz:
1. Gera um par assimétrico **RSA-4096 bits** com expoente $e = 65537$.
2. Cria o diretório local `backend/keys/`.
3. Salva a chave privada em formato PKCS#8: `backend/keys/private_key.pem`.
4. Salva a chave pública em formato SubjectPublicKeyInfo: `backend/keys/public_key.pem`.
5. Valida a integridade do par recém-gerado.

> [!IMPORTANT]
> Se as chaves já existirem, o script **não as sobrescreve**, protegendo chaves previamente criadas.

---

## 8. Verificar a Proteção das Chaves

A segurança da criptografia assimétrica baseia-se na custódia segura da chave privada:

1. **Confira a presença das chaves locais**:
   - `backend/keys/private_key.pem`
   - `backend/keys/public_key.pem`
2. **Confirme a regra de segurança do Git**:
   Verifique se o Git está ignorando as chaves executando:
   ```bash
   git status
   ```
   Os arquivos `.pem` **NÃO** devem aparecer na lista de arquivos não rastreados (*Untracked files*).
3. **Regra de Ouro**:
   **NUNCA** copie, envie por mensagem ou compartilhe o arquivo `private_key.pem`. A chave privada deve permanecer unicamente no computador que a gerou.

---

## 9. Configurar o Tailscale

*(Caso deseje testar localmente em um único computador, você pode pular diretamente para a seção 12 e utilizar `127.0.0.1`).*

Para comunicação entre computadores em redes diferentes:
1. Baixe e instale o Tailscale nos computadores da **Alice** e do **Bob**.
2. Abra o aplicativo do Tailscale em ambas as máquinas e realize o login.

---

## 10. Colocar Alice e Bob na Mesma Tailnet

Certifique-se de que os dois computadores pertencem à mesma rede virtual (*tailnet*):
- No aplicativo do Tailscale ou pelo painel web ([login.tailscale.com/admin/machines](https://login.tailscale.com/admin/machines)), verifique se o computador da Alice e o computador do Bob aparecem listados como **Connected**.
- O Tailscale cria um túnel seguro criptografado ponto a ponto com WireGuard, permitindo comunicação direta sem necessidade de abrir portas no roteador doméstico (*Port Forwarding*).

---

## 11. Descobrir o IP Tailscale da Alice

No computador da **Alice**, descubra o endereço IP atribuído pelo Tailscale:

### Via linha de comando:
```bash
tailscale ip -4
```

### Via interface gráfica do Tailscale:
Clique com o botão direito no ícone do Tailscale na bandeja do sistema e copie o endereço IP no formato:
```text
100.x.y.z
```

Anote esse endereço, pois ele será utilizado pelo Bob na etapa de conexão.

---

## 12. Iniciar o Servidor da Alice

No computador da **Alice** (com o `.venv` ativado na pasta `backend`):

Execute o servidor TCP configurado para escutar em todas as interfaces de rede (`0.0.0.0`) na porta `5000`:

### No Windows:
```powershell
python -m network.alice_server --host 0.0.0.0 --port 5000
```

### No Linux:
```bash
python3 -m network.alice_server --host 0.0.0.0 --port 5000
```

O terminal exibirá o banner inicial:
```text
========================================
       ALICE - SERVIDOR TCP
========================================

Servidor aguardando conexão...

IP:
0.0.0.0

Porta:
5000

Diretório de chaves locais:
.../backend/keys
```

---

## 13. Iniciar o Cliente do Bob

No computador do **Bob** (com o `.venv` ativado na pasta `backend`):

Substitua `<IP_TAILSCALE_ALICE>` pelo endereço IP anotado na Etapa 11 (ex.: `100.72.180.17`):

### No Windows:
```powershell
python -m network.bob_client --host <IP_TAILSCALE_ALICE> --port 5000
```

### No Linux:
```bash
python3 -m network.bob_client --host <IP_TAILSCALE_ALICE> --port 5000
```

### Simulação Local (no mesmo computador da Alice):
Se estiver testando os dois participantes na mesma máquina:
1. No Terminal 1: Inicie a Alice em `127.0.0.1`:
   ```powershell
   python -m network.alice_server --host 127.0.0.1 --port 5000
   ```
2. No Terminal 2: Gere as chaves de teste do Bob e execute:
   ```powershell
   python .\generate_bob_test_keys.py
   python -m network.bob_client --host 127.0.0.1 --port 5000 --keys-dir test_keys/bob
   ```

---

## 14. Enviar Mensagens Criptografadas

Assim que o Bob se conectar, o handshake ocorrerá automaticamente:

1. **Handshake de Chaves Públicas**:
   - Alice transmite sua chave pública para Bob e recebe a chave pública dele.
   - Bob recebe a chave pública de Alice e envia a sua.
   - Ambos validam que as chaves possuem **4096 bits**.
   - As chaves públicas do interlocutor ficam salvas **apenas em memória**.
2. **Envio da Primeira Mensagem (Alice → Bob)**:
   - Alice digita a mensagem no prompt:
     ```text
     Mensagem para Bob:
     Olá Bob, nossa comunicação está protegida por RSA-4096!
     ```
   - O terminal da Alice exibe o bloco cifrado de **512 bytes** codificado em Base64 e confirma o envio pelo TCP.
3. **Recepção e Decifragem no Bob**:
   - O terminal do Bob exibe o recebimento do ciphertext pela rede.
   - Bob decifra os dados com sua **chave privada local**.
   - O texto original em claro é exibido na tela.
4. **Resposta do Bob (Bob → Alice)**:
   - Bob digita a resposta no terminal:
     ```text
     Mensagem para Alice:
     Recebido com sucesso, Alice! Minha resposta também vai cifrada.
     ```
   - Bob cifra com a **chave pública da Alice** e transmite via TCP.
   - Alice decifra utilizando sua **chave privada local**.

---

## 15. Encerrar a Conexão com /sair

Para encerrar o chat com segurança e fechar os sockets graciosamente:

1. Digite no terminal (seja na Alice ou no Bob):
   ```text
   /sair
   ```
2. O sistema transmitirá um pacote do tipo `disconnect`.
3. Os sockets TCP serão fechados de forma limpa em ambas as pontas, liberando as portas do sistema operacional.

---

## 16. Solução de Problemas Comuns (Troubleshooting)

### 16.1. Erro: `ConnectionRefusedError` (Conexão Recusada)
- **Causa**: O cliente Bob tentou se conectar antes de o servidor da Alice estar em execução, ou o IP/porta informados estão incorretos.
- **Solução**:
  1. Certifique-se de que a Alice foi iniciada primeiro e exibe `"Servidor aguardando conexão..."`.
  2. Verifique se o IP informado no parâmetro `--host` do Bob é exatamente o IP Tailscale da Alice.
  3. No terminal do Bob, teste a conectividade com:
     ```bash
     tailscale ping <IP_TAILSCALE_ALICE>
     ```

### 16.2. Erro: `OSError: [WinError 10048] Only one usage of each socket address is normally permitted`
- **Causa**: A porta TCP `5000` já está em uso por outro processo ou por uma instância anterior do chat que não foi fechada.
- **Solução**:
  - Feche terminais antigos que estejam rodando o servidor.
  - Ou encerre o processo preso na porta 5000 (Windows PowerShell):
    ```powershell
    Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess | Stop-Process -Force
    ```
  - Ou inicie o servidor e o cliente em outra porta, por exemplo `--port 5001`.

### 16.3. Bloqueio pelo Firewall do Windows
- **Causa**: O Firewall do Windows bloqueou a abertura de portas do Python na rede pública/privada.
- **Solução**:
  1. Abra as **Configurações do Firewall do Windows**.
  2. Permita a passagem de tráfego de entrada para o executável `python.exe` na porta TCP 5000.
  3. Nas propriedades de rede do Tailscale, certifique-se de que a conexão está autorizada.

### 16.4. Erro: `KeyManagerError: As chaves locais não foram encontradas`
- **Causa**: O servidor ou cliente foi iniciado antes de gerar as chaves RSA.
- **Solução**:
  Execute no diretório `backend`:
  ```powershell
  python .\crypto\key_manager.py
  ```

### 16.5. Erro: `A mensagem excede o limite permitido para RSA-4096 com OAEP/SHA-256`
- **Causa**: Foi digitada uma mensagem com mais de **446 bytes UTF-8**.
- **Fundamento**: A especificação RFC 8017 para RSA-4096 com padding OAEP e SHA-256 impõe a capacidade útil máxima calculada por:
  $$\text{Capacidade} = 512 - (2 \times 32) - 2 = 446 \text{ bytes}$$
- **Solução**: Divida mensagens muito longas em partes menores.

### 16.6. Caracteres Acentuados Quebrados no Terminal do Windows
- **Causa**: O console do Windows pode estar configurado em *Code Page* legado (CP850 ou CP1252).
- **Solução**:
  Execute antes de rodar os scripts:
  ```powershell
  chcp 65001
  ```
  *(O código do projeto já efetua reconfiguração automática via `sys.stdout.reconfigure(encoding="utf-8")`).*
