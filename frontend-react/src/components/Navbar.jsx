import { motion as Motion } from 'framer-motion'
import { NavLink } from 'react-router-dom'

const navItems = [
  { label: 'Analyze', path: '/analyzer' },
  { label: 'Executive Dashboard', path: '/dashboard' },
  { label: 'Monitor', path: '/monitor' },
  { label: 'Upload', path: '/upload' },
]

function Navbar() {
  return (
    <Motion.header
      initial={{ opacity: 0, y: -18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className="glass-card neon-panel sticky top-4 z-30 rounded-[28px] px-4 py-4 sm:px-6"
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-[#00E5FF]/25 bg-[#00E5FF]/10 shadow-[0_0_25px_rgba(0,229,255,0.18)]">
            <div className="h-6 w-6 rounded-full border border-[#00FF9F]/60 bg-[radial-gradient(circle,#00FF9F_0%,rgba(0,255,159,0.15)_70%)]" />
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.42em] text-[#00E5FF]">Dark Web & Cyber Intelligence Unit</p>
            <h1 className="mt-1 text-xl font-semibold text-white sm:text-2xl">
              C I T A D E L
            </h1>
          </div>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="terminal-text flex items-center gap-2 rounded-full border border-[#00FF9F]/25 bg-[#00FF9F]/8 px-3 py-1.5 text-[11px] uppercase tracking-[0.26em] text-[#B8FFE3]">
            <span className="live-dot h-2.5 w-2.5 rounded-full bg-[#00FF9F] shadow-[0_0_12px_rgba(0,255,159,0.7)]" />
            Live neural link
          </div>

          <nav className="flex flex-wrap gap-2 rounded-full border border-white/6 bg-black/10 p-1.5">
            {navItems.map((item) => (
              <NavLink key={item.path} to={item.path}>
                {({ isActive }) => (
                  <Motion.span
                    whileHover={{ y: -1, scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    className={`inline-flex rounded-full px-4 py-2 text-sm font-medium transition ${
                      isActive
                        ? 'bg-[linear-gradient(135deg,rgba(0,229,255,0.18),rgba(0,255,159,0.14))] text-[#E6FDFF] shadow-[0_0_20px_rgba(0,229,255,0.18)]'
                        : 'text-slate-300 hover:bg-white/8 hover:text-white'
                    }`}
                  >
                    {item.label}
                  </Motion.span>
                )}
              </NavLink>
            ))}
          </nav>
        </div>
      </div>
    </Motion.header>
  )
}

export default Navbar
