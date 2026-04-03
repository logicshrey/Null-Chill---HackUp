import axios from 'axios'

const api = axios.create({
  baseURL: 'http://127.0.0.1:8000',
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

export const collectIntel = async (query, persist = true, demo = false) => {
  const response = await api.post('/collect-intel', { query, persist, demo })
  return response.data
}

export default api
