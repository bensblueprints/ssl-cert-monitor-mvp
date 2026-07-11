async function req(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...options,
    body: options.body != null ? JSON.stringify(options.body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

export const api = {
  me: () => req('/api/me'),
  login: (password) => req('/api/login', { method: 'POST', body: { password } }),
  logout: () => req('/api/logout', { method: 'POST' }),
  domains: () => req('/api/domains'),
  createDomain: (body) => req('/api/domains', { method: 'POST', body }),
  updateDomain: (id, body) => req(`/api/domains/${id}`, { method: 'PUT', body }),
  deleteDomain: (id) => req(`/api/domains/${id}`, { method: 'DELETE' }),
  pauseDomain: (id) => req(`/api/domains/${id}/pause`, { method: 'POST' }),
  checkNow: (id) => req(`/api/domains/${id}/check`, { method: 'POST' }),
  testAlert: (id) => req(`/api/domains/${id}/test-alert`, { method: 'POST' }),
  history: (id) => req(`/api/domains/${id}/history`),
  alerts: () => req('/api/alerts')
};

export function fmtDate(ms) {
  return ms ? new Date(ms).toLocaleDateString() : '—';
}
