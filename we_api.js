(() => {
  const tokenKey = 'we_token';

  const rawBase = String(window.WE_API_BASE || '').trim();
  const apiBase = rawBase.replace(/\/+$/, '');

  const siteBase = new URL('.', document.baseURI).toString();

  function siteUrl(path) {
    return new URL(path, siteBase).toString();
  }

  function getToken() {
    try { return localStorage.getItem(tokenKey) || ''; } catch { return ''; }
  }

  function setToken(token) {
    try {
      if (token) localStorage.setItem(tokenKey, token);
      else localStorage.removeItem(tokenKey);
    } catch {}
  }

  function isGithubPages() {
    const h = String(location.hostname || '').toLowerCase();
    return h === 'github.io' || h.endsWith('.github.io');
  }

  function backendHint() {
    if (isGithubPages() && !apiBase) {
      return 'Backend niet ingesteld. Vul WE_API_BASE in we_config.js met je backend-URL (Render/Railway), anders werken /api/* calls niet op GitHub Pages.';
    }
    return '';
  }

  async function apiFetch(path, opts = {}) {
    const url = apiBase ? (apiBase + path) : path;
    const headers = new Headers(opts.headers || {});

    const token = getToken();
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', 'Bearer ' + token);
    }

    return fetch(url, {
      ...opts,
      headers,
      credentials: 'include'
    });
  }

  async function apiPostJson(path, body, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    const res = await apiFetch(path, {
      ...opts,
      method: opts.method || 'POST',
      headers,
      body: JSON.stringify(body)
    });

    let data = null;
    try { data = await res.json(); } catch {}

    return { res, data };
  }

  window.WE = Object.assign(window.WE || {}, {
    apiBase,
    siteBase,
    siteUrl,
    getToken,
    setToken,
    backendHint,
    apiFetch,
    apiPostJson
  });
})();
