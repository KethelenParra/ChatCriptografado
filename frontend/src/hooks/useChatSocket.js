import { useCallback, useEffect, useRef, useState } from "react";
import { WS_URL } from "../services/api.js";

export function useChatSocket() {
  const socketRef = useRef(null);
  const reconnectRef = useRef(null);
  const [connected, setConnected] = useState(false);
  const [status, setStatus] = useState(null);
  const [messages, setMessages] = useState([]);
  const [error, setError] = useState("");

  const handleEvent = useCallback((event) => {
    if (event.type === "status") {
      setStatus(event);
      return;
    }
    if (event.type === "error") {
      setError(event.message || "Erro na sessão.");
      return;
    }
    if (event.type === "peer_key") {
      setStatus((current) => ({
        ...(current || {}),
        peer_key_received: true,
        peer_public_fingerprint: event.fingerprint,
      }));
      return;
    }
    if (event.type === "message") {
      setMessages((current) => [...current, event]);
      return;
    }
    if (event.type === "message_ack") {
      setMessages((current) =>
        current.map((item) =>
          item.message_id === event.message_id
            ? { ...item, delivery_status: "decrypted_by_peer" }
            : item,
        ),
      );
    }
  }, []);

  const connectSocket = useCallback(() => {
    if (socketRef.current && socketRef.current.readyState <= 1) {
      return;
    }
    const socket = new WebSocket(WS_URL);
    socketRef.current = socket;

    socket.onopen = () => {
      setConnected(true);
      setError("");
    };
    socket.onmessage = (raw) => {
      try {
        handleEvent(JSON.parse(raw.data));
      } catch {
        setError("Evento WebSocket inválido.");
      }
    };
    socket.onclose = () => {
      setConnected(false);
      reconnectRef.current = window.setTimeout(connectSocket, 1500);
    };
    socket.onerror = () => {
      setError("Não foi possível conectar ao FastAPI local (WebSocket).");
    };
  }, [handleEvent]);

  useEffect(() => {
    connectSocket();
    return () => {
      if (reconnectRef.current) {
        window.clearTimeout(reconnectRef.current);
      }
      if (socketRef.current) {
        socketRef.current.onclose = null;
        socketRef.current.close();
      }
    };
  }, [connectSocket]);

  const sendAction = useCallback((payload) => {
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      setError("WebSocket local desconectado. Verifique se o FastAPI está em execução.");
      return;
    }
    socket.send(JSON.stringify(payload));
  }, []);

  const clearError = useCallback(() => setError(""), []);

  return {
    connected,
    status,
    messages,
    error,
    sendAction,
    clearError,
  };
}
