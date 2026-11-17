import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import Layout from "./components/Layout";
import { LiveProvider } from "./live";
import AlertDetailPage from "./pages/AlertDetail";
import AlertsPage from "./pages/Alerts";
import EventsPage from "./pages/Events";
import IngestPage from "./pages/Ingest";
import LoginPage from "./pages/Login";
import OverviewPage from "./pages/Overview";
import RulesPage from "./pages/Rules";
import SimulatorPage from "./pages/Simulator";
import "./styles.css";

function App() {
  const { user, loading } = useAuth();
  if (loading) return <div className="boot">Loading…</div>;
  if (!user) return <LoginPage />;
  return (
    <LiveProvider key={user.username}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<OverviewPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="alerts/:id" element={<AlertDetailPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="rules" element={<RulesPage />} />
          <Route path="simulator" element={<SimulatorPage />} />
          <Route path="ingest" element={<IngestPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </LiveProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
