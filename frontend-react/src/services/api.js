import axios from 'axios'

function resolveApiBaseUrl() {
  const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL
  if (configuredBaseUrl) {
    return configuredBaseUrl
  }

  if (typeof window !== 'undefined') {
    const { protocol, hostname } = window.location
    return `${protocol}//${hostname}:8000`
  }

  return 'http://127.0.0.1:8000'
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

export default api
