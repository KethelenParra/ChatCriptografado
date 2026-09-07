export default function Header({ status }) {
  const localUser = status?.local_user || "—";
  const connection = status?.connection_status || "disconnected";
  const labels = {
    connected: "Conectado",
    waiting: "Aguardando o outro participante",
    connecting: "Conectando",
    disconnected: "Desconectado",
    error: "Erro de conexão",
  };

  return (
    <header className="header">
      <div className="brand">
        <p className="brand-kicker">Atividade acadêmica · TCP + RSA</p>
        <h1>Chat Criptografado</h1>
      </div>
      <div className="header-meta">
        <span className="who">{localUser}</span>
        <span className={`status status-${connection}`}>
          <i />
          {labels[connection] || connection}
        </span>
      </div>
    </header>
  );
}
