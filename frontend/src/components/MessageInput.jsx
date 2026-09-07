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
        placeholder="Digite sua mensagem..."
        disabled={disabled}
        rows={2}
      />
      <div className="composer-side">
        <span className={tooLong ? "warn" : ""}>
          {bytes} / {MAX_BYTES} bytes
        </span>
        {tooLong ? <small>A mensagem excede 446 bytes UTF-8.</small> : null}
        <button type="submit" disabled={disabled || empty || tooLong}>
          ➤
        </button>
      </div>
    </form>
  );
}
