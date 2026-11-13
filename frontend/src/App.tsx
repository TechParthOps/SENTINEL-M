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
import PlannedPage from "./pages/PlannedPage";

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
          <Route path="/virtual-office" element={<PlannedPage phase={6} />} />
          <Route path="/hunting" element={<PlannedPage phase={4} />} />
          <Route path="/network" element={<PlannedPage phase={2} />} />
          <Route path="/endpoint" element={<PlannedPage phase={2} />} />
          <Route path="/identity" element={<PlannedPage phase={2} />} />
          <Route path="/ai-security" element={<PlannedPage phase={3} />} />
          <Route path="/multimodal" element={<PlannedPage phase={3} />} />
          <Route path="/intelligence" element={<PlannedPage phase={2} />} />
          <Route path="/agents" element={<PlannedPage phase={4} />} />
          <Route path="/deception" element={<PlannedPage phase={5} />} />
          <Route path="/forensics" element={<PlannedPage phase={4} />} />
          <Route path="/playbooks" element={<PlannedPage phase={5} />} />
          <Route path="/reports" element={<PlannedPage phase={7} />} />
          <Route path="/integrations" element={<PlannedPage phase={2} />} />
          <Route path="*" element={<Overview />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}