"""Gerencia conexões WebSocket locais do navegador.

O WebSocket NÃO substitui o TCP entre Alice e Bob. Ele só leva eventos
do FastAPI local até o React que está aberto neste computador.
"""

from __future__ import annotations

from typing import Any

from fastapi import WebSocket


class WebSocketManager:
    """Registra abas locais e envia eventos em broadcast."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def send_personal(self, websocket: WebSocket, event: dict[str, Any]) -> None:
        await websocket.send_json(event)

    async def broadcast(self, event: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for connection in list(self._connections):
            try:
                await connection.send_json(event)
            except Exception:
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)
