const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
const WS_URL = import.meta.env.VITE_WS_URL || "ws://127.0.0.1:8000/ws";

export async function getHealth() {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new Error("O FastAPI local não respondeu em /health.");
  }
  return response.json();
}

export async function getStatus() {
  const response = await fetch(`${API_BASE_URL}/api/status`);
  if (!response.ok) {
    throw new Error("Não foi possível obter o status da sessão.");
  }
  return response.json();
}

export { API_BASE_URL, WS_URL };
