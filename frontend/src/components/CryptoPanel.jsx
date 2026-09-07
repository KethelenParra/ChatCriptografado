export default function CryptoPanel({ message }) {
  if (!message) {
    return (
      <aside className="crypto-panel">
        <h2>Painel criptográfico</h2>
        <p className="placeholder">
          Selecione uma mensagem para visualizar os detalhes criptográficos.
        </p>
      </aside>
    );
  }

  const sent = message.direction === "sent";
  let delivery = "DESCRIPTOGRAFADA COM SUCESSO";
  if (sent && message.delivery_status === "sent_waiting") {
    delivery = "ENVIADA — AGUARDANDO CONFIRMAÇÃO";
  } else if (sent && message.delivery_status === "decrypted_by_peer") {
    delivery = "DESCRIPTOGRAFADA PELO DESTINATÁRIO ✅";
  }

  async function copyCiphertext() {
    await navigator.clipboard.writeText(message.ciphertext || "");
  }

  return (
    <aside className="crypto-panel">
      <h2>Painel criptográfico</h2>
      <dl>
        <div><dt>Remetente</dt><dd>{message.sender}</dd></div>
        <div><dt>Destinatário</dt><dd>{message.recipient}</dd></div>
        <div><dt>Direção</dt><dd>{sent ? "Enviada" : "Recebida"}</dd></div>
        <div><dt>Algoritmo</dt><dd>{message.algorithm}</dd></div>
        <div><dt>Padding</dt><dd>{message.padding}</dd></div>
        <div><dt>Hash</dt><dd>{message.hash}</dd></div>
        <div><dt>Mensagem local</dt><dd>{message.plaintext}</dd></div>
        <div><dt>Tamanho original</dt><dd>{message.plaintext_size} bytes UTF-8</dd></div>
        <div><dt>Criptografada com</dt><dd>{message.encrypted_with}</dd></div>
        {message.decrypted_with ? (
          <div><dt>Descriptografada com</dt><dd>{message.decrypted_with}</dd></div>
        ) : null}
        <div>
          <dt>Ciphertext</dt>
          <dd>
            <pre>{message.ciphertext}</pre>
            <button type="button" className="ghost" onClick={copyCiphertext}>
              Copiar ciphertext
            </button>
          </dd>
        </div>
        <div><dt>Tamanho ciphertext</dt><dd>{message.ciphertext_size} bytes</dd></div>
        <div><dt>Mensagem original no pacote TCP</dt><dd>{message.original_in_tcp ? "SIM" : "NÃO ✅"}</dd></div>
        <div><dt>Status</dt><dd>{delivery}</dd></div>
      </dl>
    </aside>
  );
}
