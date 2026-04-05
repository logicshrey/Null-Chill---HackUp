import axios from 'axios'

const DEFAULT_BACKEND_PORT = import.meta.env.VITE_API_PORT || '8001'

export function resolveApiBaseUrl() {
  const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL
  if (configuredBaseUrl) {
    return configuredBaseUrl
  }

  if (typeof window !== 'undefined') {
    const { protocol, hostname } = window.location
    return `${protocol}//${hostname}:${DEFAULT_BACKEND_PORT}`
  }

  return `http://127.0.0.1:${DEFAULT_BACKEND_PORT}`
}

const api = axios.create({
  baseURL: resolveApiBaseUrl(),
  timeout: 15000,
})

export const analyzeText = async (text) => {
  const response = await api.post('/analyze', { text })
  return response.data
}

export const getAlerts = async () => {
  const response = await api.get('/alerts')
  return response.data
}

export const getStats = async () => {
  const response = await api.get('/stats')
  return response.data
}

export const getHealth = async () => {
  const response = await api.get('/health', { timeout: 5000 })
  return response.data
}

export const collectIntel = async (query, persist = true, demo = false) => {
  const response = await api.post('/collect-intel', { query, persist, demo }, { timeout: 60000 })
  return response.data
}

export const getMonitoringStats = async () => {
  const response = await api.get('/monitoring/stats')
  return response.data
}

export const getCases = async ({ limit = 200, status, priority, search } = {}) => {
  const response = await api.get('/cases', {
    params: {
      limit,
      ...(status ? { status } : {}),
      ...(priority ? { priority } : {}),
      ...(search ? { search } : {}),
    },
  })
  return response.data
}

export const getCase = async (caseId) => {
  const response = await api.get(`/cases/${caseId}`)
  return response.data
}

export const updateCase = async (caseId, payload) => {
  const response = await api.patch(`/cases/${caseId}`, payload)
  return response.data
}

export const getWatchlists = async () => {
  const response = await api.get('/watchlists')
  return response.data
}

export const createWatchlist = async (payload) => {
  const response = await api.post('/watchlists', payload)
  return response.data
}

export const updateWatchlist = async (watchlistId, payload) => {
  const response = await api.put(`/watchlists/${watchlistId}`, payload)
  return response.data
}

export const deleteWatchlist = async (watchlistId) => {
  const response = await api.delete(`/watchlists/${watchlistId}`)
  return response.data
}

export const runWatchlistNow = async (watchlistId) => {
  const response = await api.post(`/watchlists/${watchlistId}/run`)
  return response.data
}

export const getAuditEvents = async (limit = 100) => {
  const response = await api.get('/audit-events', { params: { limit } })
  return response.data
}

export const exportCasesSnapshot = async () => {
  const response = await api.get('/cases/export')
  return response.data
}

export default api
