"""Aplicação FastAPI local.

React conversa só com este processo, via HTTP/WebSocket. A comunicação
remota Alice/Bob continua sendo TCP Socket + RSA-4096.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from api.websocket_manager import WebSocketManager
from services.chat_runtime import ChatRuntime, ChatRuntimeError

SENTINEL = object()

CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]


def create_app(runtime: ChatRuntime) -> FastAPI:
    manager = WebSocketManager()
    pump_task: dict[str, asyncio.Task] = {}

    async def pump_events() -> None:
        """Consome a fila thread-safe e envia eventos ao React."""
        while True:
            event = await asyncio.to_thread(runtime.events.get)
            if event is SENTINEL:
                break
            await manager.broadcast(event)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        pump_task["task"] = asyncio.create_task(pump_events())
        try:
            yield
        finally:
            runtime.disconnect()
            runtime.events.put(SENTINEL)
            task = pump_task.get("task")
            if task is not None:
                try:
                    await asyncio.wait_for(task, timeout=3)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    task.cancel()

    app = FastAPI(
        title="ChatCriptografado",
        description="Ponte local React ↔ TCP/RSA. O WebSocket não substitui o TCP.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    def _friendly_error(error: Exception) -> str:
        text = str(error)
        lowered = text.lower()
        if "recusada" in lowered or "refused" in lowered:
            return "Alice indisponível. Conexão recusada."
        if "446" in text:
            return "A mensagem excede o limite de 446 bytes UTF-8."
        if "pública" in lowered and "não" in lowered:
            return "A chave pública do outro participante ainda não foi recebida."
        if "conexão tcp" in lowered or "não há conexão" in lowered:
            return "O servidor ainda não foi iniciado ou a conexão foi encerrada."
        return text

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/status")
    def api_status() -> dict[str, Any]:
        payload = runtime.get_status()
        payload["type"] = "status"
        return payload

    def _handle_action(action_payload: dict[str, Any]) -> dict[str, Any] | None:
        action = action_payload.get("action")
        try:
            if action == "connect":
                runtime.start()
                return None
            if action == "disconnect":
                runtime.disconnect()
                return None
            if action == "send_message":
                message = action_payload.get("message", "")
                runtime.send_message(message)
                return None
            if action == "get_status":
                payload = runtime.get_status()
                payload["type"] = "status"
                return payload
            return {
                "type": "error",
                "message": f"Ação desconhecida: {action!r}",
            }
        except ChatRuntimeError as error:
            return {"type": "error", "message": _friendly_error(error)}

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await manager.connect(websocket)
        status = runtime.get_status()
        status["type"] = "status"
        await manager.send_personal(websocket, status)
        try:
            while True:
                payload = await websocket.receive_json()
                if not isinstance(payload, dict):
                    await manager.send_personal(
                        websocket,
                        {"type": "error", "message": "O comando precisa ser um objeto JSON."},
                    )
                    continue
                response = await asyncio.to_thread(_handle_action, payload)
                if response is not None:
                    await manager.send_personal(websocket, response)
        except WebSocketDisconnect:
            manager.disconnect(websocket)
        except Exception:
            manager.disconnect(websocket)

    return app
