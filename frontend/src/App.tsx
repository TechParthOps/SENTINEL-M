import { useEffect } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import AppLayout from "./components/AppLayout";
import { useAuth } from "./store/auth";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import LiveOps from "./pages/LiveOps";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import AssetsPage from "./pages/AssetsPage";
import RulesPage from "./pages/RulesPage";
import HealthPage from "./pages/HealthPage";
import CoveragePage from "./pages/CoveragePage";
import SettingsPage from "./pages/SettingsPage";
import IntelligencePage from "./pages/IntelligencePage";
import NetworkPage from "./pages/NetworkPage";
import EndpointPage from "./pages/EndpointPage";
import MalwarePage from "./pages/MalwarePage";
import IdentityPage from "./pages/IdentityPage";
import AISecurityPage from "./pages/AISecurityPage";
import MultimodalPage from "./pages/MultimodalPage";
import VirtualOfficePage from "./pages/VirtualOfficePage";
import IntegrationsPage from "./pages/IntegrationsPage";
import ForensicsPage from "./pages/ForensicsPage";
import ReportsPage from "./pages/ReportsPage";
import AgentsPage from "./pages/AgentsPage";
import HuntPage from "./pages/HuntPage";
import ResponsePage from "./pages/ResponsePage";
import DeceptionPage from "./pages/DeceptionPage";

export default function App() {
  const user = useAuth((s) => s.user);
  const restore = useAuth((s) => s.restore);

  useEffect(() => {
    restore();
  }, [restore]);

  if (!user) return <Login />;

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<AppLayout />}>
          <Route path="/overview" element={<Overview />} />
          <Route path="/live" element={<LiveOps />} />
          <Route path="/threat-detection" element={<Alerts />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/health" element={<HealthPage />} />
          <Route path="/capabilities" element={<CoveragePage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/intelligence" element={<IntelligencePage />} />
          <Route path="/malware" element={<MalwarePage />} />
          <Route path="/hunting" element={<HuntPage />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route path="/endpoint" element={<EndpointPage />} />
          <Route path="/identity" element={<IdentityPage />} />
          <Route path="/ai-security" element={<AISecurityPage />} />
          <Route path="/multimodal" element={<MultimodalPage />} />
          <Route path="/virtual-office" element={<VirtualOfficePage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/deception" element={<DeceptionPage />} />
          <Route path="/forensics" element={<ForensicsPage />} />
          <Route path="/playbooks" element={<ResponsePage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/integrations" element={<IntegrationsPage />} />
          <Route path="*" element={<Overview />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}