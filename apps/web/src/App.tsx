import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './AuthContext.tsx';
import Layout from './components/Layout.tsx';
import LandingPage from './pages/Landing.tsx';
import DashboardPage from './pages/Dashboard.tsx';
import InvestigatePage from './pages/Investigate.tsx';
import InvestigationPage from './pages/InvestigationDetail.tsx';
import HistoryPage from './pages/History.tsx';
import SettingsPage from './pages/Settings.tsx';
import DocsPage from './pages/Docs.tsx';
import PrivacyPage from './pages/Privacy.tsx';
import TermsPage from './pages/Terms.tsx';
import GraphPage from './pages/Graph.tsx';
import OsintFrameworkPage from './pages/OsintFramework.tsx';

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public routes with nav */}
          <Route element={<Layout />}>
            <Route path="/" element={<LandingPage />} />
            <Route path="/docs" element={<DocsPage />} />
            <Route path="/privacy" element={<PrivacyPage />} />
            <Route path="/terms" element={<TermsPage />} />
            <Route path="/framework" element={<OsintFrameworkPage />} />
          </Route>

          {/* Auth routes redirected directly to /investigate */}
          <Route path="/login" element={<Navigate to="/investigate" replace />} />
          <Route path="/signup" element={<Navigate to="/investigate" replace />} />

          {/* App routes with sidebar */}
          <Route element={<Layout showSidebar />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/investigate" element={<InvestigatePage />} />
            <Route path="/framework" element={<OsintFrameworkPage />} />
            <Route path="/investigations/:id" element={<InvestigationPage />} />
            <Route path="/investigations/:id/graph" element={<GraphPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
