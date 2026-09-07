"""Launcher da interface gráfica (FastAPI local + sessão TCP/RSA).

O FastAPI escuta só neste computador. O canal remoto continua sendo o
TCP Socket entre Alice (servidor) e Bob (cliente).
"""

from __future__ import annotations

import argparse
import sys

import uvicorn

from api.app import create_app
from services.chat_runtime import ROLE_ALICE, ROLE_BOB, ChatRuntime


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sobe o FastAPI local e prepara a sessão TCP/RSA."
    )
    parser.add_argument(
        "--role",
        required=True,
        choices=[ROLE_ALICE, ROLE_BOB],
        help="Papel nesta máquina: alice (servidor TCP) ou bob (cliente TCP).",
    )
    parser.add_argument(
        "--tcp-host",
        default="0.0.0.0",
        help="Alice: endereço de escuta TCP. Padrão 0.0.0.0.",
    )
    parser.add_argument(
        "--peer-host",
        default=None,
        help="Bob: endereço TCP da Alice (por exemplo o IP Tailscale).",
    )
    parser.add_argument("--tcp-port", type=int, default=5000, help="Porta TCP.")
    parser.add_argument(
        "--keys-dir",
        default="keys",
        help="Diretório das chaves locais, relativo a backend/.",
    )
    parser.add_argument("--api-host", default="127.0.0.1", help="Host local do FastAPI.")
    parser.add_argument("--api-port", type=int, default=8000, help="Porta local do FastAPI.")
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    if args.role == ROLE_BOB and not args.peer_host:
        print("Bob precisa de --peer-host com o endereço da Alice.")
        return 1

    runtime = ChatRuntime(
        role=args.role,
        tcp_host=args.tcp_host,
        tcp_port=args.tcp_port,
        keys_dir=args.keys_dir,
        peer_host=args.peer_host,
    )
    app = create_app(runtime)

    print("========================================")
    print("     CHAT CRIPTOGRAFADO — INTERFACE")
    print("========================================")
    print(f"Papel: {runtime.local_user}")
    print(f"FastAPI local: http://{args.api_host}:{args.api_port}")
    print("WebSocket local: ponte React <-> Python")
    print("TCP: canal remoto Alice <-> Bob (RSA-4096)")
    print("A conexão TCP NÃO inicia sozinha. Use o botão na interface.")
    print("========================================")

    uvicorn.run(app, host=args.api_host, port=args.api_port, log_level="info")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    raise SystemExit(main())
