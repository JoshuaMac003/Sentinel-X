import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { OverviewPage } from "./pages/OverviewPage";
import { TopologyPage } from "./pages/TopologyPage";
import { AssetsPage } from "./pages/AssetsPage";
import { VulnerabilitiesPage } from "./pages/VulnerabilitiesPage";
import { AttackPathsPage } from "./pages/AttackPathsPage";
import { SimulationPage } from "./pages/SimulationPage";
import { RiskPage } from "./pages/RiskPage";

export default function App() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/topology" element={<TopologyPage />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="/attack-paths" element={<AttackPathsPage />} />
        <Route path="/simulations" element={<SimulationPage />} />
        <Route path="/risk" element={<RiskPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
