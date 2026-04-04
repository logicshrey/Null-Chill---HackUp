import { Navigate, Route, Routes } from 'react-router-dom'
import { AnimatePresence, motion as Motion } from 'framer-motion'
import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import Navbar from './components/Navbar'
import Analyzer from './pages/Analyzer'
import Dashboard from './pages/Dashboard'
import Feed from './pages/Feed'
import Upload from './pages/Upload'
import { getHealth } from './services/api'

function BackgroundParticles() {
  const particles = Array.from({ length: 14 }, (_, index) => ({
    id: index,
    size: 4 + (index % 4) * 2,
    left: `${8 + ((index * 7) % 84)}%`,
    top: `${10 + ((index * 11) % 78)}%`,
    duration: 5 + (index % 5),
    delay: index * 0.3,
  }))

  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      {particles.map((particle) => (
        <Motion.span
          key={particle.id}
          className="absolute rounded-full bg-[#00E5FF]/70 shadow-[0_0_18px_rgba(0,229,255,0.35)]"
          style={{
            width: particle.size,
            height: particle.size,
            left: particle.left,
            top: particle.top,
          }}
          animate={{ y: [0, -18, 0], opacity: [0.15, 0.7, 0.15] }}
          transition={{
            duration: particle.duration,
            repeat: Infinity,
            ease: 'easeInOut',
            delay: particle.delay,
          }}
        />
      ))}
    </div>
  )
}

function App() {
  const location = useLocation()
  const [backendWarning, setBackendWarning] = useState('')

  useEffect(() => {
    let active = true

    const checkBackend = async () => {
      try {
        await getHealth()
        if (active) {
          setBackendWarning('')
        }
      } catch {
        if (active) {
          setBackendWarning('Backend health check failed. If live analysis still works, refresh once while the service finishes recovering.')
        }
      }
    }

    checkBackend()
    const intervalId = window.setInterval(checkBackend, 10000)
    return () => {
      active = false
      window.clearInterval(intervalId)
    }
  }, [])

  return (
    <div className="min-h-screen overflow-hidden bg-[#020617] text-[#E2E8F0]">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(0,229,255,0.12),transparent_28%),radial-gradient(circle_at_bottom_right,rgba(0,255,159,0.12),transparent_26%),radial-gradient(circle_at_center,rgba(255,59,59,0.06),transparent_22%)]" />
        <div className="absolute left-0 top-0 h-[28rem] w-[28rem] rounded-full bg-[#00E5FF]/10 blur-3xl" />
        <div className="absolute bottom-0 right-0 h-[30rem] w-[30rem] rounded-full bg-[#00FF9F]/10 blur-3xl" />
        <div className="absolute left-1/2 top-1/3 h-96 w-96 -translate-x-1/2 rounded-full bg-[#FFC857]/6 blur-3xl" />
        <div className="cyber-grid absolute inset-0 opacity-45" />
        <div className="mesh-overlay absolute inset-0 opacity-45" />
        <BackgroundParticles />
      </div>

      <div className="relative mx-auto flex min-h-screen w-full max-w-[1600px] flex-col px-4 py-5 sm:px-6 lg:px-8">
        <Navbar />
        {backendWarning && (
          <div className="mt-4 rounded-2xl border border-[#FF3B3B]/35 bg-[#FF3B3B]/10 px-4 py-3 text-sm text-[#FECACA] shadow-[0_0_28px_rgba(255,59,59,0.08)]">
            {backendWarning}
          </div>
        )}
        <Motion.main
          className="flex-1 py-6"
        >
          <AnimatePresence mode="wait">
            <Routes location={location} key={location.pathname}>
              <Route path="/" element={<Navigate to="/analyzer" replace />} />
              <Route path="/analyzer" element={<Analyzer />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/feed" element={<Feed />} />
              <Route path="/upload" element={<Upload />} />
            </Routes>
          </AnimatePresence>
        </Motion.main>
      </div>
    </div>
  )
}

export default App
