export default function ConnectionPanel({ status, onConnect, onDisconnect }) {
  const role = status?.role;
  const connection = status?.connection_status || "disconnected";
  const canStart = connection === "disconnected" || connection === "error";

  return (
    <section className="connection-panel">
      <div>
        <p><span className="label">Papel</span> {role === "alice" ? "Servidor TCP" : "Cliente TCP"}</p>
        <p><span className="label">Porta</span> {status?.tcp_port || 5000}</p>
        <p><span className="label">Chave RSA local</span> {status?.local_key_loaded ? "Carregada ✅" : "Ausente"}</p>
        <p><span className="label">Chave privada local</span> {status?.private_key_available ? "Disponível" : "Ausente"}</p>
        <p><span className="label">Chave pública do outro</span> {status?.peer_key_received ? "Recebida ✅" : "Aguardando"}</p>
        {status?.peer_public_fingerprint ? (
          <p className="fingerprint">Fingerprint: {status.peer_public_fingerprint}</p>
        ) : null}
      </div>
      <div className="connection-actions">
        {role === "alice" && connection !== "connected" ? (
          <button type="button" onClick={onConnect} disabled={!canStart}>
            {connection === "waiting" ? "Aguardando Bob..." : "Iniciar servidor"}
          </button>
        ) : null}
        {role === "bob" && connection !== "connected" ? (
          <button type="button" onClick={onConnect} disabled={connection === "connecting"}>
            {connection === "connecting" ? "Conectando..." : "Conectar à Alice"}
          </button>
        ) : null}
        {connection === "connected" || connection === "waiting" ? (
          <button type="button" className="ghost" onClick={onDisconnect}>
            Desconectar
          </button>
        ) : null}
      </div>
    </section>
  );
}
