function formatTime(timestamp) {
  if (!timestamp) return "";
  try {
    return new Date(timestamp).toLocaleTimeString("pt-BR", {
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "";
  }
}

export default function MessageBubble({ message, selected, onSelect }) {
  const sent = message.direction === "sent";
  return (
    <article className={`bubble ${sent ? "sent" : "received"} ${selected ? "selected" : ""}`}>
      <header>
        <strong>{message.sender}</strong>
        <time>{formatTime(message.timestamp)}</time>
      </header>
      <p>{message.plaintext}</p>
      <button type="button" className="linkish" onClick={() => onSelect(message)}>
        🔐 Ver mensagem criptografada
      </button>
    </article>
  );
}
