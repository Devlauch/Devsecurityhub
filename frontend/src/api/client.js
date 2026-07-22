import axios from 'axios';

const api = axios.create({ baseURL: '/api' });

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('sechub_token');
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

api.interceptors.response.use(
  r => r,
  async err => {
    const cfg = err.config;
    const status = err.response?.status;

    // Auto-retry on network errors or 5xx (not on 4xx — those are real errors)
    if (status !== 401 && status !== 400 && status !== 404 && status !== 409) {
      cfg._retries = (cfg._retries || 0) + 1;
      if (cfg._retries <= 3) {
        await new Promise(r => setTimeout(r, 1200 * cfg._retries));
        return api(cfg);
      }
    }

    if (status === 401) {
      localStorage.removeItem('sechub_token');
      localStorage.removeItem('sechub_user');
      window.location.href = '/login';
    }

    return Promise.reject(err);
  }
);

export default api;
