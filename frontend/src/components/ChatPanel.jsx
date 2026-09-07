import MessageBubble from "./MessageBubble.jsx";

export default function ChatPanel({ messages, selectedMessage, onSelect }) {
  return (
    <section className="chat-panel">
      <header className="pane-head">
        <h2>Conversa</h2>
        <p>As mensagens ficam apenas nesta sessão do navegador.</p>
      </header>
      <div className="chat-log">
        {messages.length === 0 ? (
          <div className="empty">
            <p>Nenhuma mensagem nesta sessão.</p>
            <p>Inicie a conexão TCP e envie a primeira linha pelo campo abaixo.</p>
          </div>
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
