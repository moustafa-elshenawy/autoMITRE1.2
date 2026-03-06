import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { AuthProvider } from './contexts/AuthContext'
import ProtectedRoute from './components/ProtectedRoute'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import SavedThreats from './pages/SavedThreats'
import ThreatAnalysis from './pages/ThreatAnalysis'
import RiskHeatmap from './pages/RiskHeatmap'
import FrameworkCoverage from './pages/FrameworkCoverage'
import AIChat from './pages/AIChat'
import ThreatFeed from './pages/ThreatFeed'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import Profile from './pages/Profile'
import Mitigations from './pages/Mitigations'
import Login from './pages/Login'
import Register from './pages/Register'
import './index.css'

function Topbar({ title, subtitle }) {
  return (
    <div className="topbar">
      <div className="topbar-content">
        <h1>{title}</h1>
        <div className="subtitle">{subtitle}</div>
      </div>
    </div>
  )
}

const pages = {
  '/': { title: 'Dashboard', subtitle: 'Threat intelligence overview and real-time monitoring' },
  '/saved-threats': { title: 'Saved Threats', subtitle: 'Historical archive of processed analyses' },
  '/analyze': { title: 'Threat Analysis', subtitle: 'Analyze threats with AI-powered MITRE ATT&CK mapping' },
  '/heatmap': { title: 'Risk Heatmap', subtitle: 'Interactive risk matrix visualization' },
  '/coverage': { title: 'Framework Coverage', subtitle: 'MITRE ATT&CK, D3FEND, NIST SP 800-53, OWASP mapping' },
  '/mitigations': { title: 'Mitigations & Predictions', subtitle: 'Predictive analysis and defense strategies' },
  '/chat': { title: 'AI Risk Assessment', subtitle: 'Conversational AI threat analyst' },
  '/feed': { title: 'Threat Intelligence Feed', subtitle: 'Live cyber threat intelligence' },
  '/reports': { title: 'Reports & Export', subtitle: 'Generate STIX 2.1, JSON, CSV, and SIEM exports' },
  '/settings': { title: 'Settings', subtitle: 'Configure APIs, integrations, and preferences' },
  '/profile': { title: 'User Profile', subtitle: 'Manage your account settings and preferences' },
}

function AppLayout({ children }) {
  const path = window.location.pathname
  const page = pages[path] || { title: '404', subtitle: 'Not Found' }

  return (
    <div className="app-layout">
      <div className="scan-line" />
      <Sidebar />
      <div className="main-content">
        <Topbar title={page.title} subtitle={page.subtitle} />
        <div className="page-content">
          {children}
        </div>
      </div>
    </div>
  )
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Protected Routes */}
          <Route element={<ProtectedRoute />}>
            <Route path="/" element={<AppLayout><Dashboard /></AppLayout>} />
            <Route path="/saved-threats" element={<AppLayout><SavedThreats /></AppLayout>} />
            <Route path="/analyze" element={<AppLayout><ThreatAnalysis /></AppLayout>} />
            <Route path="/heatmap" element={<AppLayout><RiskHeatmap /></AppLayout>} />
            <Route path="/coverage" element={<AppLayout><FrameworkCoverage /></AppLayout>} />
            <Route path="/mitigations" element={<AppLayout><Mitigations /></AppLayout>} />
            <Route path="/chat" element={<AppLayout><AIChat /></AppLayout>} />
            <Route path="/feed" element={<AppLayout><ThreatFeed /></AppLayout>} />
            <Route path="/reports" element={<AppLayout><Reports /></AppLayout>} />
            <Route path="/settings" element={<AppLayout><Settings /></AppLayout>} />
            <Route path="/profile" element={<AppLayout><Profile /></AppLayout>} />
          </Route>
        </Routes>
      </Router>
    </AuthProvider>
  )
}

export default App
