function Row({ label, children }) {
  return (
    <div className="spec-row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export default function CryptoPanel({ message }) {
  if (!message) {
    return (
      <aside className="crypto-panel">
        <header className="pane-head">
          <h2>Inspeção da cifra</h2>
          <p>Detalhes reais da mensagem selecionada.</p>
        </header>
        <div className="empty">
          <p>Nenhuma mensagem selecionada.</p>
          <p>Escolha uma linha na conversa para ver o ciphertext e o método usado.</p>
        </div>
      </aside>
    );
  }

  const sent = message.direction === "sent";
  let delivery = "Descriptografada com sucesso";
  if (sent && message.delivery_status === "sent_waiting") {
    delivery = "Enviada, aguardando confirmação";
  } else if (sent && message.delivery_status === "decrypted_by_peer") {
    delivery = "Descriptografada pelo destinatário";
  }

  async function copyCiphertext() {
    await navigator.clipboard.writeText(message.ciphertext || "");
  }

  return (
    <aside className="crypto-panel">
      <header className="pane-head">
        <h2>Inspeção da cifra</h2>
        <p>
          {message.sender} → {message.recipient}
        </p>
      </header>
      <dl className="spec">
        <Row label="Direção">{sent ? "Enviada" : "Recebida"}</Row>
        <Row label="Algoritmo">{message.algorithm}</Row>
        <Row label="Padding">{message.padding}</Row>
        <Row label="Hash">{message.hash}</Row>
        <Row label="Texto local">{message.plaintext}</Row>
        <Row label="Tamanho">{message.plaintext_size} bytes UTF-8</Row>
        <Row label="Cifrada com">{message.encrypted_with}</Row>
        {message.decrypted_with ? (
          <Row label="Decifrada com">{message.decrypted_with}</Row>
        ) : null}
        <Row label="Ciphertext">
          <pre>{message.ciphertext}</pre>
          <button type="button" className="ghost compact" onClick={copyCiphertext}>
            Copiar
          </button>
        </Row>
        <Row label="Bloco RSA">{message.ciphertext_size} bytes</Row>
        <Row label="Texto no pacote TCP">{message.original_in_tcp ? "Sim" : "Não"}</Row>
        <Row label="Estado">{delivery}</Row>
      </dl>
    </aside>
  );
}
