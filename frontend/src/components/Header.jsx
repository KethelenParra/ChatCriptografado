export default function Header({ status }) {
  const localUser = status?.local_user || "—";
  const connection = status?.connection_status || "disconnected";
  const labels = {
    connected: "Conectado",
    waiting: "Aguardando Bob",
    connecting: "Conectando",
    disconnected: "Desconectado",
    error: "Erro",
  };

  return (
    <header className="header">
      <div>
        <h1>🔐 RSA CHAT</h1>
        <p className="subtle">RSA-4096 • OAEP • SHA-256</p>
      </div>
      <div className="header-meta">
        <strong>{localUser}</strong>
        <span className={`status-pill status-${connection}`}>
          ● {labels[connection] || connection}
        </span>
      </div>
    </header>
  );
}
