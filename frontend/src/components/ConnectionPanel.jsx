function KeyState({ ok, okLabel, waitLabel }) {
  return (
    <span className={ok ? "ok" : "muted"}>
      {ok ? okLabel : waitLabel}
    </span>
  );
}

export default function ConnectionPanel({ status, onConnect, onDisconnect }) {
  const role = status?.role;
  const connection = status?.connection_status || "disconnected";
  const canStart = connection === "disconnected" || connection === "error";
  const showDisconnect = connection === "connected" || connection === "waiting";

  return (
    <section className="toolbar">
      <ul className="meta-row">
        <li>
          <span>Função</span>
          {role === "alice" ? "Servidor TCP" : "Cliente TCP"}
        </li>
        <li>
          <span>Porta</span>
          {status?.tcp_port || 5000}
        </li>
        <li>
          <span>Cifra</span>
          RSA-4096, OAEP, SHA-256
        </li>
        <li>
          <span>Chaves locais</span>
          <KeyState ok={status?.local_key_loaded} okLabel="Prontas" waitLabel="Ausentes" />
        </li>
        <li>
          <span>Pública remota</span>
          <KeyState ok={status?.peer_key_received} okLabel="Recebida" waitLabel="Pendente" />
        </li>
      </ul>
      {status?.peer_public_fingerprint ? (
        <p className="fingerprint">Fingerprint da pública remota {status.peer_public_fingerprint}</p>
      ) : null}
      <div className="toolbar-actions">
        {role === "alice" && connection !== "connected" ? (
          <button type="button" className="primary" onClick={onConnect} disabled={!canStart}>
            {connection === "waiting" ? "Aguardando conexão" : "Iniciar servidor"}
          </button>
        ) : null}
        {role === "bob" && connection !== "connected" ? (
          <button type="button" className="primary" onClick={onConnect} disabled={connection === "connecting"}>
            {connection === "connecting" ? "Conectando" : "Conectar à Alice"}
          </button>
        ) : null}
        {showDisconnect ? (
          <button type="button" className="ghost" onClick={onDisconnect}>
            Encerrar sessão
          </button>
        ) : null}
      </div>
    </section>
  );
}
