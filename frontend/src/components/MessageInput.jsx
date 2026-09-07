import { useState } from "react";

const MAX_BYTES = 446;

export default function MessageInput({ disabled, onSend }) {
  const [text, setText] = useState("");
  const bytes = new TextEncoder().encode(text).length;
  const tooLong = bytes > MAX_BYTES;
  const empty = text.trim().length === 0;

  function submit() {
    if (disabled || empty || tooLong) return;
    onSend(text);
    setText("");
  }

  function handleKeyDown(event) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      submit();
    }
  }

  return (
    <form
      className="composer"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <textarea
        value={text}
        onChange={(event) => setText(event.target.value)}
        onKeyDown={handleKeyDown}
        placeholder={disabled ? "Conecte-se para escrever" : "Escrever mensagem"}
        disabled={disabled}
        rows={1}
      />
      <div className="composer-meta">
        <span className={tooLong ? "warn" : "count"}>
          {bytes} / {MAX_BYTES} bytes
        </span>
        {tooLong ? <span className="warn">Limite UTF-8 excedido</span> : null}
        <button type="submit" className="primary compact" disabled={disabled || empty || tooLong}>
          Enviar
        </button>
      </div>
    </form>
  );
}
