
import { NavLink } from "react-router-dom";

const links = [
  { to: "/", label: "Overview" },
  { to: "/topology", label: "Digital Twin" },
  { to: "/assets", label: "Assets" },
  { to: "/vulnerabilities", label: "Vulnerabilities" },
  { to: "/attack-paths", label: "Attack Paths" },
  { to: "/simulations", label: "Attack Simulation" },
  { to: "/risk", label: "Risk" },
  { to: "/sdn", label: "SDN Monitoring" },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen">
      <header className="border-b border-[var(--border)] bg-[color-mix(in_srgb,var(--bg-elevated)_88%,transparent)] backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="mono text-xs tracking-[0.2em] text-[var(--accent)]">
              SENTINEL-X · REVIEW 2
            </p>
            <h1 className="text-2xl font-semibold tracking-tight md:text-3xl">
              Smart Hospital Digital Twin & Attack Simulator
            </h1>
            <p className="mt-1 max-w-2xl text-sm text-[var(--muted)]">
              Analytical cyber-risk simulation platform — synthetic infrastructure only.
              Deterministic rule-based graph propagation.
            </p>
          </div>
          <div className="panel px-3 py-2 text-xs text-[var(--muted)]">
            MODEL → SIMULATE → ANALYZE
          </div>
        </div>

        <nav className="mx-auto flex max-w-7xl gap-1 overflow-x-auto px-4 pb-3">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === "/"}
              className={({ isActive }) =>
                `whitespace-nowrap rounded-lg px-3 py-2 text-sm transition ${
                  isActive
                    ? "bg-[var(--accent)] text-white"
                    : "text-[var(--muted)] hover:bg-[var(--bg-panel)] hover:text-[var(--text)]"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6">
        {children}
      </main>
    </div>
  );
}
