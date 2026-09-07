import MessageBubble from "./MessageBubble.jsx";

export default function ChatPanel({ messages, selectedMessage, onSelect }) {
  return (
    <section className="chat-panel">
      <h2>Chat</h2>
      <div className="chat-log">
        {messages.length === 0 ? (
          <p className="placeholder">Nenhuma mensagem ainda. A conversa permanece só na memória desta página.</p>
        ) : (
          messages.map((message) => (
            <MessageBubble
              key={message.message_id}
              message={message}
              selected={selectedMessage?.message_id === message.message_id}
              onSelect={onSelect}
            />
          ))
        )}
      </div>
    </section>
  );
}
