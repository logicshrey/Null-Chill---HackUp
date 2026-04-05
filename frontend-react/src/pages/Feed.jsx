import { useEffect, useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import CaseDetailPanel from '../components/CaseDetailPanel'
import Loader from '../components/Loader'
import RiskBadge from '../components/RiskBadge'
import StatCard from '../components/StatCard'
import Toast from '../components/Toast'
import WatchlistManager from '../components/WatchlistManager'
import {
  createWatchlist,
  deleteWatchlist,
  exportCasesSnapshot,
  getAuditEvents,
  getCase,
  getCases,
  getMonitoringStats,
  getWatchlists,
  resolveApiBaseUrl,
  runWatchlistNow,
  updateCase,
  updateWatchlist,
} from '../services/api'

function Feed() {
  const [stats, setStats] = useState(null)
  const [cases, setCases] = useState([])
  const [watchlists, setWatchlists] = useState([])
  const [auditEvents, setAuditEvents] = useState([])
  const [selectedCaseId, setSelectedCaseId] = useState('')
  const [selectedCase, setSelectedCase] = useState(null)
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState('')
  const [liveState, setLiveState] = useState('connecting')
  const [busyWatchlistId, setBusyWatchlistId] = useState('')
  const [filters, setFilters] = useState({
    status: '',
    priority: '',
    search: '',
  })

  const loadMonitoring = async ({ preserveCase = true } = {}) => {
    const [statsResponse, casesResponse, watchlistsResponse, auditResponse] = await Promise.all([
      getMonitoringStats(),
      getCases({
        status: filters.status || undefined,
        priority: filters.priority || undefined,
        search: filters.search || undefined,
      }),
      getWatchlists(),
      getAuditEvents(12),
    ])

    setStats(statsResponse)
    setCases(casesResponse.cases || [])
    setWatchlists(watchlistsResponse.watchlists || [])
    setAuditEvents(auditResponse.events || [])

    const nextSelectedId = preserveCase ? selectedCaseId || casesResponse.cases?.[0]?.id : casesResponse.cases?.[0]?.id
    if (nextSelectedId) {
      setSelectedCaseId(nextSelectedId)
      setSelectedCase(await getCase(nextSelectedId))
    } else {
      setSelectedCaseId('')
      setSelectedCase(null)
    }
  }

  useEffect(() => {
    let active = true

    const boot = async () => {
      try {
        await loadMonitoring({ preserveCase: false })
        if (active) {
          setToast('')
        }
      } catch (apiError) {
        if (active) {
          setToast(apiError?.response?.data?.detail || 'Monitoring workspace failed to load.')
        }
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    boot()

    return () => {
      active = false
    }
  }, [filters.status, filters.priority, filters.search])

  useEffect(() => {
    if (!selectedCaseId) {
      return undefined
    }

    let active = true
    const loadCase = async () => {
      try {
        const response = await getCase(selectedCaseId)
        if (active) {
          setSelectedCase(response)
        }
      } catch {
        if (active) {
          setSelectedCase(null)
        }
      }
    }

    loadCase()
    return () => {
      active = false
    }
  }, [selectedCaseId])

  useEffect(() => {
    const eventSource = new EventSource(`${resolveApiBaseUrl()}/events/stream`)

    eventSource.onopen = () => setLiveState('live')
    eventSource.onmessage = async (event) => {
      try {
        const payload = JSON.parse(event.data)
        if (payload.event_type === 'case_updated') {
          setToast(`Case ${payload.action === 'created' ? 'created' : 'updated'}: ${payload.case?.title || 'exposure case'}`)
          await loadMonitoring()
        } else if (payload.event_type === 'watchlist_error') {
          setToast(payload.message || 'Watchlist run failed.')
        }
      } catch {
        setLiveState('degraded')
      }
    }
    eventSource.onerror = () => {
      setLiveState('degraded')
    }

    return () => {
      eventSource.close()
    }
  }, [selectedCaseId, filters.status, filters.priority, filters.search])

  useEffect(() => {
    if (!toast) {
      return undefined
    }
    const timeoutId = window.setTimeout(() => setToast(''), 4000)
    return () => window.clearTimeout(timeoutId)
  }, [toast])

  const handleCreateWatchlist = async (payload) => {
    try {
      await createWatchlist(payload)
      setToast('Watchlist created. It will start monitoring on the next scheduler cycle.')
      await loadMonitoring({ preserveCase: false })
    } catch (apiError) {
      setToast(apiError?.response?.data?.detail || 'Watchlist creation failed.')
    }
  }

  const handleRunWatchlist = async (watchlistId) => {
    setBusyWatchlistId(watchlistId)
    try {
      const response = await runWatchlistNow(watchlistId)
      setToast(`Watchlist run completed with ${response.case_count || 0} case update(s).`)
      await loadMonitoring()
    } catch (apiError) {
      setToast(apiError?.response?.data?.detail || 'Watchlist run failed.')
    } finally {
      setBusyWatchlistId('')
    }
  }

  const handleToggleWatchlist = async (watchlist) => {
    try {
      await updateWatchlist(watchlist.id, { ...watchlist, enabled: !watchlist.enabled })
      setToast(`Watchlist ${watchlist.enabled ? 'disabled' : 'enabled'}.`)
      await loadMonitoring()
    } catch (apiError) {
      setToast(apiError?.response?.data?.detail || 'Watchlist update failed.')
    }
  }

  const handleDeleteWatchlist = async (watchlistId) => {
    try {
      await deleteWatchlist(watchlistId)
      setToast('Watchlist deleted.')
      await loadMonitoring()
    } catch (apiError) {
      setToast(apiError?.response?.data?.detail || 'Watchlist deletion failed.')
    }
  }

  const handleSaveCase = async (caseId, payload) => {
    try {
      await updateCase(caseId, payload)
      setToast('Case workflow updated.')
      await loadMonitoring()
    } catch (apiError) {
      setToast(apiError?.response?.data?.detail || 'Case update failed.')
    }
  }

  const handleExport = async () => {
    try {
      const snapshot = await exportCasesSnapshot()
      const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = 'exposure-monitoring-snapshot.json'
      anchor.click()
      URL.revokeObjectURL(url)
      setToast('Monitoring snapshot exported.')
    } catch (apiError) {
      setToast(apiError?.response?.data?.detail || 'Export failed.')
    }
  }

  const latestTimestamp = useMemo(() => {
    return selectedCase?.last_seen ? new Date(selectedCase.last_seen).toLocaleString() : 'No recent case'
  }, [selectedCase])

  return (
    <div className="space-y-6">
      <Toast message={toast} />
      <Motion.section initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="glass-card neon-panel rounded-[32px] p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.38em] text-[#FF3B3B]">Exposure Monitoring Workspace</p>
            <h2 className="mt-3 text-4xl font-semibold text-white">Continuous watchlists and live case inbox</h2>
            <p className="mt-4 max-w-3xl text-sm text-slate-300">
              Track exposure cases in near real time, monitor saved watchlists, and triage the cases that matter most to the organization.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div className="terminal-text rounded-2xl border border-white/8 bg-black/15 px-4 py-3 text-sm text-slate-300">
              last update {latestTimestamp}
            </div>
            <div
              className={`terminal-text flex items-center gap-2 rounded-full border px-4 py-2 text-[11px] uppercase tracking-[0.3em] ${
                liveState === 'live'
                  ? 'border-[#00FF9F]/35 bg-[#00FF9F]/10 text-[#B8FFE0]'
                  : 'border-[#FFC857]/35 bg-[#FFC857]/10 text-[#FFD98C]'
              }`}
            >
              <span className={`h-2.5 w-2.5 rounded-full ${liveState === 'live' ? 'bg-[#00FF9F]' : 'bg-[#FFC857]'}`} />
              {liveState === 'live' ? 'Live' : 'Degraded'}
            </div>
            <button
              type="button"
              onClick={handleExport}
              className="terminal-text rounded-full border border-[#00E5FF]/25 bg-[#00E5FF]/10 px-4 py-2 text-[11px] uppercase tracking-[0.24em] text-[#A8F3FF]"
            >
              Export Snapshot
            </button>
          </div>
        </div>
      </Motion.section>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Active Cases" value={stats?.active_cases ?? '--'} accent="#00E5FF" icon="AC" />
        <StatCard label="Critical Cases" value={stats?.critical_cases ?? '--'} accent="#FF3B3B" icon="CC" pulse />
        <StatCard label="Watchlists" value={stats?.enabled_watchlists ?? '--'} accent="#00FF9F" icon="WL" />
        <StatCard label="New 24h" value={stats?.new_cases_24h ?? '--'} accent="#FFC857" icon="24" />
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
        <WatchlistManager
          watchlists={watchlists}
          onCreate={handleCreateWatchlist}
          onRun={handleRunWatchlist}
          onToggle={handleToggleWatchlist}
          onDelete={handleDeleteWatchlist}
          busyWatchlistId={busyWatchlistId}
        />

        <div className="space-y-6">
          <Motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="glass-card neon-panel rounded-[32px] p-6">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Case Inbox</p>
                <h3 className="mt-2 text-2xl font-semibold text-white">Prioritized exposure cases</h3>
              </div>
              <div className="grid gap-3 sm:grid-cols-3">
                <input
                  value={filters.search}
                  onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))}
                  className="rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                  placeholder="Search assets or indicators"
                />
                <select
                  value={filters.status}
                  onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}
                  className="rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                >
                  <option value="">All statuses</option>
                  <option value="new">New</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                </select>
                <select
                  value={filters.priority}
                  onChange={(event) => setFilters((current) => ({ ...current, priority: event.target.value }))}
                  className="rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                >
                  <option value="">All priorities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
            </div>

            {loading ? (
              <div className="mt-6">
                <Loader label="Loading monitoring workspace..." />
              </div>
            ) : cases.length ? (
              <div className="mt-6 feed-scroll max-h-[38rem] space-y-3 overflow-y-auto pr-1">
                {cases.map((caseItem) => (
                  <button
                    key={caseItem.id}
                    type="button"
                    onClick={() => setSelectedCaseId(caseItem.id)}
                    className={`w-full rounded-[24px] border p-4 text-left transition ${
                      selectedCaseId === caseItem.id
                        ? 'border-[#00E5FF]/35 bg-[#00E5FF]/8'
                        : 'border-white/8 bg-black/10 hover:border-[#00E5FF]/20'
                    }`}
                  >
                    <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                      <div>
                        <p className="text-lg font-semibold text-white">{caseItem.title}</p>
                        <p className="mt-2 text-sm text-slate-300">{caseItem.summary}</p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <RiskBadge level={caseItem.risk_level || 'LOW'} />
                        <div className="terminal-text rounded-full border border-[#00E5FF]/20 bg-[#00E5FF]/10 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#A8F3FF]">
                          {caseItem.priority}
                        </div>
                        <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300">
                          {caseItem.case_status}
                        </div>
                      </div>
                    </div>
                    <div className="mt-4 grid gap-3 md:grid-cols-3">
                      <div>
                        <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Assets</p>
                        <p className="mt-1 text-sm text-slate-200">{caseItem.affected_assets?.slice(0, 3).join(', ') || 'Unknown assets'}</p>
                      </div>
                      <div>
                        <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Exposure</p>
                        <p className="mt-1 text-sm text-slate-200">{caseItem.estimated_total_records_label}</p>
                      </div>
                      <div>
                        <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Sources</p>
                        <p className="mt-1 text-sm text-slate-200">{caseItem.sources?.map((source) => source.source).join(', ') || 'No sources yet'}</p>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <div className="mt-6 rounded-[24px] border border-white/8 bg-black/10 px-4 py-12 text-center text-slate-400">
                No exposure cases yet. Run a watchlist or manual source collection to generate cases.
              </div>
            )}
          </Motion.section>

          <CaseDetailPanel selectedCase={selectedCase} onSave={handleSaveCase} />

          <Motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="glass-card neon-panel rounded-[32px] p-6">
            <div>
              <p className="text-xs uppercase tracking-[0.35em] text-[#FFC857]">Audit Trail</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Recent system actions</h3>
            </div>
            <div className="mt-6 space-y-3">
              {auditEvents.map((eventItem) => (
                <div key={eventItem.id} className="rounded-[20px] border border-white/8 bg-black/10 p-4">
                  <p className="text-sm font-semibold text-white">{eventItem.event_type.replaceAll('_', ' ')}</p>
                  <p className="mt-2 text-sm text-slate-300">
                    {eventItem.watchlist_name || eventItem.watchlist_id || eventItem.target || 'system'}
                  </p>
                  <p className="mt-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                    {eventItem.timestamp ? new Date(eventItem.timestamp).toLocaleString() : 'No timestamp'}
                  </p>
                </div>
              ))}
              {!auditEvents.length ? <p className="text-sm text-slate-400">No audit events yet.</p> : null}
            </div>
          </Motion.section>
        </div>
      </div>
    </div>
  )
}

export default Feed
