"""Pacote de comunicação TCP do ChatCriptografado.

Alice atua como servidor e Bob como cliente. Cada computador usa o
próprio par RSA em backend/keys/. A confidencialidade vem do RSA-4096
com OAEP/SHA-256, não do TCP.
"""

from __future__ import annotations

from pathlib import Path

# Diretório backend/, independente da máquina em que o código roda.
BACKEND_DIR = Path(__file__).resolve().parent.parent


def resolve_keys_dir(keys_dir: str | Path) -> Path:
    """Resolve o diretório das chaves locais em relação ao backend.

    Caminhos relativos (ex.: keys ou test_keys/bob) são interpretados
    a partir de backend/. Caminhos absolutos são preservados.
    """
    path = Path(keys_dir)
    if not path.is_absolute():
        path = BACKEND_DIR / path
    return path.resolve()
