import { useEffect, useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import CircularProgress from '../components/CircularProgress'
import ExternalIntelOverview from '../components/ExternalIntelOverview'
import Loader from '../components/Loader'
import TerminalConsole from '../components/TerminalConsole'
import ThreatCard from '../components/ThreatCard'
import Toast from '../components/Toast'
import { analyzeText, collectIntel } from '../services/api'

const sampleTexts = [
  'Admin login credentials for SBI with email ops@sbi.com password=Root@123 and hidden access panel.',
  'Ransomware toolkit for sale with crypter, loader and persistence support.',
  'Phishing page ready for Microsoft 365 users with OTP relay and Telegram operator.',
]

const idleConsoleLines = [
  'Awaiting suspicious intelligence packet...',
  'Neural signature engine standing by.',
  'Regex detectors primed for credential leakage patterns.',
]

function useTypedText(value) {
  const [displayText, setDisplayText] = useState('')

  useEffect(() => {
    if (!value) {
      const timeoutId = window.setTimeout(() => setDisplayText(''), 0)
      return () => window.clearTimeout(timeoutId)
    }

    let index = 0
    const interval = window.setInterval(() => {
      index += 1
      setDisplayText(value.slice(0, index))
      if (index >= value.length) {
        window.clearInterval(interval)
      }
    }, 15)

    return () => window.clearInterval(interval)
  }, [value])

  return displayText
}

function Analyzer() {
  const [text, setText] = useState(sampleTexts[0])
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [intelQuery, setIntelQuery] = useState('sbi.com')
  const [intelResponse, setIntelResponse] = useState(null)
  const [intelLoading, setIntelLoading] = useState(false)
  const [toast, setToast] = useState('')
  const [streamFrame, setStreamFrame] = useState('')
  const [lastCaseUpdateCount, setLastCaseUpdateCount] = useState(0)

  const summaryText = useMemo(() => {
    if (!result) {
      return ''
    }

    return `Threat ${result.threat_type} detected with ${result.risk_level} risk, priority ${result.alert_priority?.priority || 'LOW'}, and ${(result.confidence_score * 100).toFixed(1)} percent confidence.`
  }, [result])

  const typedSummary = useTypedText(summaryText)
  const intelSummary = useMemo(() => {
    if (!intelResponse) {
      return ''
    }

    const collectionSummary = intelResponse.summary
    if (intelResponse.count > 0) {
      if (collectionSummary) {
        return `${intelResponse.demo_mode ? 'Generated' : 'Collected'} ${intelResponse.count} corroborated source finding${intelResponse.count > 1 ? 's' : ''} across ${collectionSummary.source_count || intelResponse.platforms?.length || 0} source${(collectionSummary.source_count || intelResponse.platforms?.length || 0) === 1 ? '' : 's'} for ${intelResponse.organization}. Combined priority is ${collectionSummary.combined_priority?.priority || 'LOW'} at score ${collectionSummary.combined_priority?.priority_score || 0}, with ${collectionSummary.estimated_total_records_label || 'unknown leak volume'}. ${lastCaseUpdateCount ? `${lastCaseUpdateCount} monitoring case${lastCaseUpdateCount === 1 ? '' : 's'} updated for the Monitor workspace.` : ''}`
      }

      return `${intelResponse.demo_mode ? 'Generated' : 'Collected'} ${intelResponse.count} source intelligence result${intelResponse.count > 1 ? 's' : ''} across ${intelResponse.platforms?.length || 0} platform${intelResponse.platforms?.length === 1 ? '' : 's'} for ${intelResponse.organization}.`
    }

    return `No high-confidence intelligence hits were ${intelResponse.demo_mode ? 'generated' : 'collected'} for ${intelResponse.organization}.`
  }, [intelResponse, lastCaseUpdateCount])
  const typedIntelSummary = useTypedText(intelSummary)

  const consoleLines = useMemo(() => {
    if (loading) {
      return [
        'Scanning dark web marketplaces...',
        'Cross-checking semantic signatures...',
        'Threat signature detected...',
        'Entity extraction pipeline active...',
      ]
    }

    if (!result) {
      return idleConsoleLines
    }

    return [
      `Threat class resolved to ${result.threat_type}.`,
      `Risk level calibrated to ${result.risk_level}.`,
      `Detected ${result.entities?.length || 0} entities and ${Object.values(result.patterns || {}).flat().length} pattern hits.`,
      `Correlation engine found ${result.correlation?.correlated_alerts_count || 0} linked alerts.`,
      `Impact score ${result.impact_assessment?.impact_score || 0}; priority ${result.alert_priority?.priority || 'LOW'}.`,
    ]
  }, [loading, result])

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      const frame = Array.from({ length: 7 }, (_, rowIndex) =>
        Array.from({ length: 30 }, (_, colIndex) => ((rowIndex * 17 + colIndex * 13 + Date.now()) % 16).toString(16).toUpperCase()).join(' '),
      ).join('\n')
      setStreamFrame(frame)
    }, 280)

    return () => window.clearInterval(intervalId)
  }, [])

  useEffect(() => {
    if (!toast) {
      return undefined
    }

    const timeoutId = window.setTimeout(() => setToast(''), 3500)
    return () => window.clearTimeout(timeoutId)
  }, [toast])

  const handleAnalyze = async () => {
    if (!text.trim()) {
      setToast('Enter suspicious content before initiating a deep scan.')
      return
    }

    setLoading(true)
    setToast('')
    setResult(null)

    try {
      const response = await analyzeText(text.trim())
      setResult(response)
    } catch (apiError) {
      setToast(
        apiError?.response?.data?.detail ||
          'Backend is unreachable. Start the FastAPI server at http://127.0.0.1:8001.',
      )
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  const handleIntelCollect = async (demo = false) => {
    if (!intelQuery.trim()) {
      setToast('Enter an organization name or domain before collecting source intelligence.')
      return
    }

    setIntelLoading(true)
    setToast('')
    setIntelResponse(null)
    setLastCaseUpdateCount(0)

    try {
      const response = await collectIntel(intelQuery.trim(), true, demo)
      setIntelResponse(response)
      setLastCaseUpdateCount(response.case_updates?.length || 0)
      if (response.count > 0) {
        setToast(
          `${demo ? 'Generated' : 'Collected'} ${response.count} intelligence result${response.count > 1 ? 's' : ''}. ${response.case_updates?.length || 0} monitoring case${(response.case_updates?.length || 0) === 1 ? '' : 's'} synced to Monitor.`,
        )
      } else {
        setToast(
          demo
            ? 'Demo generation finished, but no intelligence results were produced.'
            : 'Collection finished, but no high-confidence threat-relevant source hits were found.',
        )
      }
    } catch (apiError) {
      const isTimeout = apiError?.code === 'ECONNABORTED'
      setToast(
        apiError?.response?.data?.detail ||
          (isTimeout
            ? 'Source intelligence collection is taking longer than expected. The backend is reachable, but this query timed out in the browser.'
            : 'Source intelligence collection failed. The backend may be busy or one of the providers returned an error.'),
      )
      setIntelResponse(null)
    } finally {
      setIntelLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <Toast message={toast} />
      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <Motion.section
          initial={{ opacity: 0, x: -18 }}
          animate={{ opacity: 1, x: 0 }}
          className="glass-card neon-panel rounded-[32px] p-6"
        >
          <p className="text-xs uppercase tracking-[0.38em] text-[#00E5FF]">Neural Threat Analyzer</p>
          <h2 className="mt-3 text-4xl font-semibold text-white">Active Surveillance of High-Risk Channels</h2>
          <p className="mt-4 max-w-3xl text-sm text-slate-300">
            Interrogate suspicious marketplace posts, leak previews, phishing lures, and malware sale listings
            using the existing backend intelligence pipeline.
          </p>

          <div className="mt-6 grid gap-4 lg:grid-cols-[1fr_auto]">
            <div className="rounded-[28px] border border-[#00E5FF]/16 bg-[#020617]/82 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.02)]">
              <div className="terminal-text mb-3 text-xs uppercase tracking-[0.3em] text-slate-500">
                &gt;&gt;&gt; Enter suspicious text...
              </div>
              <textarea
                value={text}
                onChange={(event) => setText(event.target.value)}
                placeholder=">>> Enter suspicious text..."
                className="terminal-text min-h-72 w-full resize-none bg-transparent text-sm leading-7 text-slate-100 outline-none placeholder:text-slate-500"
              />
            </div>

            <div className="grid gap-4">
              <div className="glass-card rounded-[28px] px-5 py-4">
                <p className="text-xs uppercase tracking-[0.32em] text-slate-500">Threat score</p>
                <p className="mt-2 text-3xl font-semibold text-white">
                  {result ? `${Math.round(result.confidence_score * 100)}%` : '--'}
                </p>
              </div>
              <div className="glass-card rounded-[28px] px-5 py-4">
                <p className="text-xs uppercase tracking-[0.32em] text-slate-500">Signal status</p>
                <p className="mt-2 text-3xl font-semibold text-[#00FF9F]">{result?.threat_type || 'Idle'}</p>
              </div>
            </div>
          </div>

          <div className="mt-5 flex flex-wrap gap-3">
            {sampleTexts.map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() => setText(sample)}
                className="terminal-text rounded-full border border-white/10 bg-white/5 px-4 py-2 text-[11px] uppercase tracking-[0.24em] text-slate-300 transition hover:border-[#00E5FF]/35 hover:text-white"
              >
                Load sample
              </button>
            ))}
          </div>

          <div className="mt-6">
            <Motion.button
              whileTap={{ scale: 0.98 }}
              whileHover={{ scale: 1.01, y: -1 }}
              type="button"
              onClick={handleAnalyze}
              className="terminal-text rounded-[22px] bg-[linear-gradient(135deg,#00E5FF,#00FF9F)] px-6 py-3 text-sm font-bold uppercase tracking-[0.28em] text-slate-950 shadow-[0_0_28px_rgba(0,229,255,0.28)] transition"
            >
              Initiate Deep Scan
            </Motion.button>
          </div>
        </Motion.section>

        <Motion.section
          initial={{ opacity: 0, x: 18 }}
          animate={{ opacity: 1, x: 0 }}
          className="grid gap-6"
        >
          <CircularProgress
            value={result ? result.confidence_score * 100 : 6}
            riskLevel={result?.risk_level || 'LOW'}
            label="Threat level"
          />

          <div className="glass-card neon-panel rounded-[28px] p-5">
            <div className="mb-3 flex items-center justify-between">
              <p className="text-xs uppercase tracking-[0.34em] text-[#00FF9F]">Data stream</p>
              <div className="terminal-text flicker text-[11px] uppercase tracking-[0.28em] text-slate-500">
                encrypted telemetry
              </div>
            </div>
            <pre className="terminal-text flicker min-h-[220px] overflow-hidden rounded-[22px] border border-white/8 bg-[#020617]/85 p-4 text-xs leading-6 text-[#00E5FF]">
              {streamFrame}
            </pre>
          </div>
        </Motion.section>
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
        <TerminalConsole key={consoleLines.join('|')} title="System Console" lines={consoleLines} accent="#00E5FF" />

        <div className="space-y-6">
          <div className="glass-card neon-panel rounded-[28px] p-5">
            <p className="text-xs uppercase tracking-[0.34em] text-[#00FF9F]">Verdict Channel</p>
            <div className="mt-4 min-h-28 rounded-[22px] border border-white/8 bg-black/10 p-4">
              {loading ? (
                <Loader label="Running regex, NLP, and model inference..." />
              ) : typedSummary ? (
                <p className="text-lg leading-8 text-slate-100">{typedSummary}</p>
              ) : (
                <p className="text-slate-400">Run a scan to surface threat classification, extracted entities, and confidence details.</p>
              )}
            </div>
          </div>

          {result ? (
            <div className="grid gap-4 md:grid-cols-3">
              <div className="glass-card rounded-[24px] p-4">
                <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Priority</p>
                <p className="mt-3 text-2xl font-semibold text-[#FFB4B4]">{result.alert_priority?.priority || 'LOW'}</p>
              </div>
              <div className="glass-card rounded-[24px] p-4">
                <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Campaign Score</p>
                <p className="mt-3 text-2xl font-semibold text-[#00E5FF]">{result.correlation?.campaign_score || 0}</p>
              </div>
              <div className="glass-card rounded-[24px] p-4">
                <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Impact Score</p>
                <p className="mt-3 text-2xl font-semibold text-[#FFC857]">{result.impact_assessment?.impact_score || 0}</p>
              </div>
            </div>
          ) : null}

          {result ? <ThreatCard item={result} title="Threat intelligence result" /> : null}
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.92fr_1.08fr]">
        <Motion.section
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card neon-panel rounded-[32px] p-6"
        >
          <p className="text-xs uppercase tracking-[0.38em] text-[#FFC857]">External Source Intelligence</p>
          <h2 className="mt-3 text-3xl font-semibold text-white">Search by organization or domain</h2>
          <p className="mt-4 max-w-3xl text-sm text-slate-300">
            Use this space for ad hoc investigations. The results are normalized into cases so the new Monitor
            workflow can keep tracking corroborated exposure signals over time.
          </p>

          <div className="mt-6 rounded-[28px] border border-[#FFC857]/16 bg-[#020617]/82 p-4">
            <div className="terminal-text mb-3 text-xs uppercase tracking-[0.3em] text-slate-500">
              &gt;&gt;&gt; Enter organization or domain...
            </div>
            <input
              value={intelQuery}
              onChange={(event) => setIntelQuery(event.target.value)}
              placeholder="SBI or hackthecore.com"
              className="terminal-text w-full rounded-[18px] border border-white/8 bg-black/10 px-4 py-4 text-sm text-slate-100 outline-none placeholder:text-slate-500"
            />
          </div>

          <div className="mt-5 flex flex-wrap gap-3">
            {['sbi.com', 'hackthecore.com', 'SBI'].map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() => setIntelQuery(sample)}
                className="terminal-text rounded-full border border-white/10 bg-white/5 px-4 py-2 text-[11px] uppercase tracking-[0.24em] text-slate-300 transition hover:border-[#FFC857]/35 hover:text-white"
              >
                Load {sample}
              </button>
            ))}
          </div>

          <div className="mt-6 flex flex-wrap gap-4">
            <Motion.button
              whileTap={{ scale: 0.98 }}
              whileHover={{ scale: 1.01, y: -1 }}
              type="button"
              onClick={() => handleIntelCollect(false)}
              className="terminal-text rounded-[22px] bg-[linear-gradient(135deg,#FFC857,#00E5FF)] px-6 py-3 text-sm font-bold uppercase tracking-[0.28em] text-slate-950 shadow-[0_0_28px_rgba(255,200,87,0.24)] transition"
            >
              Collect Source Intel
            </Motion.button>
            <Motion.button
              whileTap={{ scale: 0.98 }}
              whileHover={{ scale: 1.01, y: -1 }}
              type="button"
              onClick={() => handleIntelCollect(true)}
              className="terminal-text rounded-[22px] border border-[#00FF9F]/25 bg-[#00FF9F]/12 px-6 py-3 text-sm font-bold uppercase tracking-[0.28em] text-[#B8FFE0] transition"
            >
              Run Demo Intel
            </Motion.button>
            <div className="glass-card rounded-[22px] px-5 py-4">
              <p className="text-xs uppercase tracking-[0.32em] text-slate-500">Pipeline sync</p>
              <p className="mt-2 text-sm font-semibold text-[#00FF9F]">
                {intelResponse?.demo_mode ? 'Demo dataset isolated from live providers' : 'Case sync to Monitor enabled'}
              </p>
            </div>
          </div>
        </Motion.section>

        <div className="space-y-6">
          <div className="glass-card neon-panel rounded-[28px] p-5">
            <p className="text-xs uppercase tracking-[0.34em] text-[#FFC857]">Collection Status</p>
            <div className="mt-4 min-h-28 rounded-[22px] border border-white/8 bg-black/10 p-4">
              {intelLoading ? (
                <Loader label="Collecting Telegram, Pastebin, and Dehashed intelligence..." />
              ) : typedIntelSummary ? (
                <p className="text-lg leading-8 text-slate-100">{typedIntelSummary}</p>
              ) : (
                <p className="text-slate-400">
                  Run a source collection to surface Telegram, Pastebin, and Dehashed findings for an organization or domain.
                </p>
              )}
            </div>
          </div>

          {intelResponse ? (
            <div className="grid gap-4 md:grid-cols-4">
              <div className="glass-card rounded-[24px] p-4">
                <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Platforms</p>
                <p className="mt-3 text-2xl font-semibold text-[#FFC857]">{intelResponse.platforms?.length || 0}</p>
              </div>
              <div className="glass-card rounded-[24px] p-4">
                <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Findings</p>
                <p className="mt-3 text-2xl font-semibold text-[#00E5FF]">{intelResponse.count || 0}</p>
              </div>
              <div className="glass-card rounded-[24px] p-4">
                <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Combined Priority</p>
                <p className="mt-3 text-2xl font-semibold text-[#00FF9F]">
                  {intelResponse.summary?.combined_priority?.priority || 'LOW'}
                </p>
              </div>
              <div className="glass-card rounded-[24px] p-4">
                <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Warnings</p>
                <p className="mt-3 text-2xl font-semibold text-[#FFB4B4]">{intelResponse.warnings?.length || 0}</p>
              </div>
            </div>
          ) : null}

          {intelResponse?.case_updates?.length ? (
            <div className="glass-card rounded-[24px] border border-[#00E5FF]/15 bg-[#00E5FF]/6 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-[#00E5FF]">Monitor Sync</p>
              <p className="mt-3 text-sm text-slate-200">
                {intelResponse.case_updates.length} case{intelResponse.case_updates.length === 1 ? '' : 's'} were created or updated in the Monitor workspace from this collection run.
              </p>
            </div>
          ) : null}

          {intelResponse?.demo_mode ? (
            <div className="glass-card rounded-[24px] border border-[#00FF9F]/15 bg-[#00FF9F]/6 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-[#00FF9F]">Demo Mode</p>
              <p className="mt-3 text-sm text-slate-200">
                These results are synthetic test records and do not replace or interfere with the real Telegram collection path.
              </p>
            </div>
          ) : null}
        </div>
      </div>

      {intelResponse?.warnings?.length ? (
        <div className="glass-card rounded-[28px] p-5">
          <p className="text-xs uppercase tracking-[0.34em] text-[#FF3B3B]">Source Collection Notes</p>
          <ul className="mt-4 space-y-2 text-sm text-slate-200">
            {intelResponse.warnings.map((warning) => (
              <li key={warning}>• {warning}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {intelResponse?.summary ? <ExternalIntelOverview summary={intelResponse.summary} /> : null}

      {intelResponse?.findings?.length ? (
        <div className="space-y-6">
          {intelResponse.findings.map((finding, index) => (
            <ThreatCard
              key={`${finding.source || 'source'}-${finding.timestamp || 'timestamp'}-${index}`}
              item={finding}
              title={`${finding.source || 'Source'} intelligence result`}
            />
          ))}
        </div>
      ) : null}
    </div>
  )
}

export default Analyzer
