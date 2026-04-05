import { useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'

function normalizeTags(value) {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
}

function WatchlistManager({ watchlists, onCreate, onRun, onToggle, onDelete, busyWatchlistId }) {
  const [form, setForm] = useState({
    name: '',
    query: '',
    owner: 'Threat Intel Team',
    business_unit: 'Security Operations',
    interval_seconds: 300,
    tags: 'brand, credentials',
    assets: '',
    description: '',
    webhook_url: '',
    demo_mode: false,
  })
  const [submitting, setSubmitting] = useState(false)

  const enabledCount = useMemo(
    () => watchlists.filter((watchlist) => watchlist.enabled).length,
    [watchlists],
  )

  const handleSubmit = async (event) => {
    event.preventDefault()
    setSubmitting(true)
    try {
      await onCreate({
        ...form,
        tags: normalizeTags(form.tags),
        assets: normalizeTags(form.assets),
        interval_seconds: Number(form.interval_seconds) || 300,
      })
      setForm((current) => ({
        ...current,
        name: '',
        query: '',
        assets: '',
        description: '',
      }))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-6">
      <Motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="glass-card neon-panel rounded-[32px] p-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.35em] text-[#FFC857]">Saved Watchlists</p>
            <h3 className="mt-2 text-2xl font-semibold text-white">Continuous monitoring targets</h3>
          </div>
          <div className="terminal-text rounded-full border border-[#00FF9F]/25 bg-[#00FF9F]/8 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#B8FFE0]">
            {enabledCount}/{watchlists.length || 0} enabled
          </div>
        </div>

        <form className="mt-6 grid gap-4 md:grid-cols-2" onSubmit={handleSubmit}>
          <label className="space-y-2">
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Watchlist Name</span>
            <input
              value={form.name}
              onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
              className="w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
              placeholder="SBI exposed credentials"
              required
            />
          </label>
          <label className="space-y-2">
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Query</span>
            <input
              value={form.query}
              onChange={(event) => setForm((current) => ({ ...current, query: event.target.value }))}
              className="w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
              placeholder="sbi.com"
              required
            />
          </label>
          <label className="space-y-2">
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Owner</span>
            <input
              value={form.owner}
              onChange={(event) => setForm((current) => ({ ...current, owner: event.target.value }))}
              className="w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
            />
          </label>
          <label className="space-y-2">
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Business Unit</span>
            <input
              value={form.business_unit}
              onChange={(event) => setForm((current) => ({ ...current, business_unit: event.target.value }))}
              className="w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
            />
          </label>
          <label className="space-y-2">
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Interval (seconds)</span>
            <input
              type="number"
              min="60"
              value={form.interval_seconds}
              onChange={(event) => setForm((current) => ({ ...current, interval_seconds: event.target.value }))}
              className="w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
            />
          </label>
          <label className="space-y-2">
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Tags</span>
            <input
              value={form.tags}
              onChange={(event) => setForm((current) => ({ ...current, tags: event.target.value }))}
              className="w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
              placeholder="brand, pii"
            />
          </label>
          <label className="space-y-2 md:col-span-2">
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Known Assets (comma separated)</span>
            <input
              value={form.assets}
              onChange={(event) => setForm((current) => ({ ...current, assets: event.target.value }))}
              className="w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
              placeholder="sbi.com, vpn.sbi.com, github.com/sbi"
            />
          </label>
          <label className="space-y-2 md:col-span-2">
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Description</span>
            <textarea
              value={form.description}
              onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
              className="min-h-28 w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
              placeholder="Track credential, infra, and public leak exposure for this organization."
            />
          </label>
          <label className="space-y-2 md:col-span-2">
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Webhook URL (optional)</span>
            <input
              value={form.webhook_url}
              onChange={(event) => setForm((current) => ({ ...current, webhook_url: event.target.value }))}
              className="w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
              placeholder="https://hooks.slack.com/services/..."
            />
          </label>

          <label className="terminal-text flex items-center gap-3 text-sm text-slate-300 md:col-span-2">
            <input
              type="checkbox"
              checked={form.demo_mode}
              onChange={(event) => setForm((current) => ({ ...current, demo_mode: event.target.checked }))}
            />
            Use demo mode for this watchlist
          </label>

          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={submitting}
              className="terminal-text rounded-[20px] bg-[linear-gradient(135deg,#FFC857,#00E5FF)] px-5 py-3 text-sm font-bold uppercase tracking-[0.24em] text-slate-950"
            >
              {submitting ? 'Saving...' : 'Create Watchlist'}
            </button>
          </div>
        </form>
      </Motion.section>

      <div className="space-y-4">
        {watchlists.map((watchlist) => (
          <div key={watchlist.id} className="glass-card rounded-[24px] p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <p className="text-lg font-semibold text-white">{watchlist.name}</p>
                <p className="mt-1 text-sm text-slate-300">{watchlist.query}</p>
                <p className="mt-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                  Owner {watchlist.owner} | {watchlist.business_unit} | every {watchlist.interval_seconds}s
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => onRun(watchlist.id)}
                  disabled={busyWatchlistId === watchlist.id}
                  className="terminal-text rounded-full border border-[#00E5FF]/20 bg-[#00E5FF]/10 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#A8F3FF]"
                >
                  {busyWatchlistId === watchlist.id ? 'Running...' : 'Run Now'}
                </button>
                <button
                  type="button"
                  onClick={() => onToggle(watchlist)}
                  className="terminal-text rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300"
                >
                  {watchlist.enabled ? 'Disable' : 'Enable'}
                </button>
                <button
                  type="button"
                  onClick={() => onDelete(watchlist.id)}
                  className="terminal-text rounded-full border border-[#FF3B3B]/30 bg-[#FF3B3B]/10 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#FFB4B4]"
                >
                  Delete
                </button>
              </div>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div>
                <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Last Run</p>
                <p className="mt-1 text-sm text-slate-200">{watchlist.last_run_at ? new Date(watchlist.last_run_at).toLocaleString() : 'Never'}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Last Result</p>
                <p className="mt-1 text-sm text-slate-200">
                  {watchlist.last_error
                    ? `Error: ${watchlist.last_error}`
                    : `Cases touched ${watchlist.last_case_count || 0} | ${watchlist.last_duration_ms || 0} ms`}
                </p>
              </div>
            </div>
          </div>
        ))}

        {!watchlists.length ? (
          <div className="rounded-[24px] border border-white/8 bg-black/10 px-4 py-10 text-center text-slate-400">
            Create the first watchlist to turn the project into continuous monitoring.
          </div>
        ) : null}
      </div>
    </div>
  )
}

export default WatchlistManager
