import { useState } from "react";
import Header from "./components/Header.jsx";
import ConnectionPanel from "./components/ConnectionPanel.jsx";
import ChatPanel from "./components/ChatPanel.jsx";
import CryptoPanel from "./components/CryptoPanel.jsx";
import MessageInput from "./components/MessageInput.jsx";
import { useChatSocket } from "./hooks/useChatSocket.js";

export default function App() {
  const { connected, status, messages, error, sendAction, clearError } = useChatSocket();
  const [selectedMessage, setSelectedMessage] = useState(null);
  const tcpReady = status?.connection_status === "connected";
  const selected = messages.find((item) => item.message_id === selectedMessage?.message_id) || null;

  return (
    <div className="shell">
      <Header status={status} />
      <ConnectionPanel
        status={status}
        onConnect={() => sendAction({ action: "connect" })}
        onDisconnect={() => sendAction({ action: "disconnect" })}
      />
      {error ? (
        <div className="notice notice-error" role="alert">
          <span>{error}</span>
          <button type="button" className="text-btn" onClick={clearError}>
            Dispensar
          </button>
        </div>
      ) : null}
      {!connected ? (
        <div className="notice">
          A interface local ainda não alcançou o FastAPI em 127.0.0.1:8000.
        </div>
      ) : null}
      <main className="workspace">
        <ChatPanel messages={messages} selectedMessage={selected} onSelect={setSelectedMessage} />
        <CryptoPanel message={selected} />
      </main>
      <MessageInput
        disabled={!tcpReady}
        onSend={(message) => sendAction({ action: "send_message", message })}
      />
    </div>
  );
}
