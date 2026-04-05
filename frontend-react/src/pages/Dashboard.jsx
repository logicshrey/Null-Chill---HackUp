import { useEffect, useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import Loader from '../components/Loader'
import StatCard from '../components/StatCard'
import TerminalConsole from '../components/TerminalConsole'
import Toast from '../components/Toast'
import { getMonitoringStats } from '../services/api'

const pieColors = ['#00CFFF', '#FF3B3B', '#00FF9F', '#8B5CF6', '#FACC15']

function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState('')

  useEffect(() => {
    const loadStats = async () => {
      setLoading(true)
      setToast('')

      try {
        const response = await getMonitoringStats()
        setStats(response)
      } catch (apiError) {
        setToast(
          apiError?.response?.data?.detail ||
            'Unable to reach the monitoring statistics endpoint. Ensure FastAPI is running.',
        )
      } finally {
        setLoading(false)
      }
    }

    loadStats()
  }, [])

  useEffect(() => {
    if (!toast) {
      return undefined
    }
    const timeoutId = window.setTimeout(() => setToast(''), 3500)
    return () => window.clearTimeout(timeoutId)
  }, [toast])

  const priorityData = useMemo(
    () => Object.entries(stats?.priority_distribution || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const statusData = useMemo(
    () => Object.entries(stats?.status_distribution || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const sourceData = useMemo(
    () => Object.entries(stats?.source_distribution || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const exposureData = useMemo(
    () => Object.entries(stats?.exposure_distribution || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const activeCases = stats?.active_cases ?? 0
  const criticalCases = stats?.critical_cases ?? 0
  const corroboratedCases = stats?.corroborated_cases ?? 0
  const watchlistHealth = stats?.watchlist_health || []
  const timelineData = (stats?.timeline || []).map((item) => ({
    bucket: item.bucket.slice(5),
    cases: item.cases,
  }))
  const consoleLines = [
    'Executive command view synchronized with the monitoring scheduler.',
    `Active cases ${activeCases}; critical cases ${criticalCases}; corroborated cases ${corroboratedCases}.`,
    `Enabled watchlists ${stats?.enabled_watchlists ?? 0}; new cases in the last 24h ${stats?.new_cases_24h ?? 0}.`,
    `Mean time to review ${stats?.mean_time_to_review_hours ?? 0} hours.`,
    `Last scheduler cycle: ${stats?.scheduler?.last_cycle_summary?.watchlists_executed ?? 0} watchlists executed.`,
  ]

  return (
    <div className="space-y-6">
      <Toast message={toast} />
      <Motion.section
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid gap-4 md:grid-cols-2 xl:grid-cols-4"
      >
        <StatCard label="Active Cases" value={stats?.active_cases ?? '--'} accent="#00E5FF" icon="AC" />
        <StatCard label="Critical Cases" value={criticalCases} accent="#FF3B3B" icon="CC" pulse />
        <StatCard label="Corroborated" value={corroboratedCases} accent="#00FF9F" icon="CO" />
        <StatCard label="New In 24h" value={stats?.new_cases_24h ?? '--'} accent="#FFC857" icon="24" />
      </Motion.section>

      {loading ? (
        <div className="glass-card rounded-[32px] p-8">
          <Loader label="Loading executive exposure dashboard..." />
        </div>
      ) : (
        <>
          <div className="grid gap-6 xl:grid-cols-[1.25fr_0.75fr]">
            <Motion.section
              initial={{ opacity: 0, x: -18 }}
              animate={{ opacity: 1, x: 0 }}
              className="glass-card neon-panel rounded-[32px] p-6"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Executive Exposure Overview</p>
                  <h2 className="mt-2 text-3xl font-semibold text-white">Case volume over time</h2>
                </div>
                <div className="terminal-text rounded-full border border-white/8 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.28em] text-slate-400">
                  real monitoring data
                </div>
              </div>

              <div className="mt-6 h-[26rem] rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(2,6,23,0.95),rgba(15,23,42,0.75))] p-4">
                {timelineData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData}>
                      <defs>
                        <linearGradient id="caseTimelineFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.45} />
                          <stop offset="100%" stopColor="#00E5FF" stopOpacity={0.04} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="bucket" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(0,229,255,0.2)', borderRadius: 16 }} />
                      <Area type="monotone" dataKey="cases" stroke="#00E5FF" fill="url(#caseTimelineFill)" strokeWidth={3} />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No timeline data available yet.</div>
                )}
              </div>
            </Motion.section>

            <Motion.section
              initial={{ opacity: 0, x: 18 }}
              animate={{ opacity: 1, x: 0 }}
              className="grid gap-4"
            >
              {[
                { label: 'Enabled Watchlists', value: stats?.enabled_watchlists ?? 0, accent: '#00FF9F' },
                { label: 'Mean Time To Review', value: stats?.mean_time_to_review_hours ?? 0, accent: '#FFC857' },
                { label: 'Case Backlog', value: activeCases, accent: '#00E5FF' },
                { label: 'Scheduler Runs', value: stats?.scheduler?.last_cycle_summary?.watchlists_executed ?? 0, accent: '#FF3B3B' },
              ].map((metric) => (
                <div key={metric.label} className="glass-card neon-panel rounded-[28px] p-5">
                  <div className="flex items-center justify-between">
                    <p className="text-xs uppercase tracking-[0.34em] text-slate-400">{metric.label}</p>
                    <p className="terminal-text text-sm" style={{ color: metric.accent }}>
                      {metric.value}
                    </p>
                  </div>
                  <div className="mt-4 h-3 overflow-hidden rounded-full bg-white/6">
                    <Motion.div
                      className="h-full rounded-full"
                      style={{ background: `linear-gradient(90deg, ${metric.accent}, transparent)` }}
                      initial={{ width: '0%' }}
                      animate={{ width: `${Math.min(100, Math.max(10, Number(metric.value) || 0))}%` }}
                      transition={{ duration: 1 }}
                    />
                  </div>
                </div>
              ))}
            </Motion.section>
          </div>

          <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr_0.8fr]">
            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Priority Distribution</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Exposure case urgency</h3>
              <div className="mt-6 h-80">
                {priorityData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={priorityData}>
                      <XAxis dataKey="name" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(0,229,255,0.2)', borderRadius: 16 }} />
                      <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                        {priorityData.map((entry) => (
                          <Cell
                            key={entry.name}
                            fill={entry.name === 'CRITICAL' ? '#FF3B3B' : entry.name === 'HIGH' ? '#FF7A7A' : entry.name === 'MEDIUM' ? '#FFC857' : '#00FF9F'}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No priority data yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#FFC857]">Workflow States</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Case triage progress</h3>
              <div className="mt-6 h-80">
                {statusData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={statusData} dataKey="value" nameKey="name" innerRadius={52} outerRadius={92} paddingAngle={4}>
                        {statusData.map((entry, index) => (
                          <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,200,87,0.2)', borderRadius: 16 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No workflow data available yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">Exposed Data Types</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Most common exposure categories</h3>
              <div className="mt-6 h-80">
                {exposureData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={exposureData}>
                      <XAxis dataKey="name" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(0,255,159,0.2)', borderRadius: 16 }} />
                      <Bar dataKey="value" radius={[12, 12, 0, 0]}>
                        {exposureData.map((entry, index) => (
                          <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No exposure breakdown available yet.</div>
                )}
              </div>
            </div>
          </div>

          <div className="grid gap-6 xl:grid-cols-[0.9fr_0.9fr_1.2fr]">
            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#FF3B3B]">Source Coverage</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Cases by monitored source</h3>
              <div className="mt-6 h-72">
                {sourceData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={sourceData}>
                      <XAxis dataKey="name" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,59,59,0.2)', borderRadius: 16 }} />
                      <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                        {sourceData.map((entry, index) => (
                          <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No source data available yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#FFC857]">Operational Readiness</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Response workflow KPIs</h3>
              <div className="mt-6 grid gap-4">
                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Mean Time To Review</p>
                  <p className="mt-3 text-3xl font-semibold text-white">{stats?.mean_time_to_review_hours ?? 0}h</p>
                </div>
                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Corroborated Cases</p>
                  <p className="mt-3 text-3xl font-semibold text-[#00E5FF]">{corroboratedCases}</p>
                </div>
                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Enabled Watchlists</p>
                  <p className="mt-3 text-3xl font-semibold text-[#FFC857]">{stats?.enabled_watchlists ?? 0}</p>
                </div>
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">Watchlist Health</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Collector performance</h3>
              <div className="mt-6 space-y-4">
                {watchlistHealth.length ? (
                  watchlistHealth.map((watchlist) => (
                    <div key={watchlist.id} className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                      <div className="flex items-center justify-between">
                        <p className="text-sm font-semibold text-white">{watchlist.name}</p>
                        <p className={`terminal-text text-[11px] uppercase tracking-[0.24em] ${watchlist.last_error ? 'text-[#FFB4B4]' : 'text-[#B8FFE0]'}`}>
                          {watchlist.last_error ? 'Attention' : 'Healthy'}
                        </p>
                      </div>
                      <p className="mt-2 text-sm text-slate-300">
                        {watchlist.last_error
                          ? watchlist.last_error
                          : `Last run ${watchlist.last_duration_ms || 0} ms, ${watchlist.last_case_count || 0} cases touched.`}
                      </p>
                      <p className="mt-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                        {watchlist.last_success_at ? `Success ${new Date(watchlist.last_success_at).toLocaleString()}` : 'No successful run yet'}
                      </p>
                    </div>
                  ))
                ) : (
                  <div className="rounded-[22px] border border-white/8 bg-black/10 p-4 text-slate-400">
                    No watchlists configured yet.
                  </div>
                )}
              </div>
            </div>
          </div>

          <TerminalConsole
            key={consoleLines.join('|')}
            title="Executive Console"
            lines={consoleLines}
            accent="#00FF9F"
            minHeight="min-h-[240px]"
          />
        </>
      )}
    </div>
  )
}

export default Dashboard
