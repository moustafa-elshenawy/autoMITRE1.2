import { useState, useEffect } from 'react'
import { Download, FileJson, FileText, Database, Zap, CheckCircle, Briefcase, ShieldAlert, BarChart, AlertCircle, Info, Loader } from 'lucide-react'
import axios from 'axios'

const API = 'http://localhost:8000'

const EXPORT_FORMATS = [
    {
        id: 'executive', isPdf: true,
        icon: <Briefcase size={22} />,
        name: 'Executive PDF',
        color: '#f43f5e',
        endpoint: '/api/export/pdf',
        contains: ['Business risk summary', 'Threat severity breakdown', 'Top vulnerabilities', 'Recommended actions for leadership'],
    },
    {
        id: 'managerial', isPdf: true,
        icon: <BarChart size={22} />,
        name: 'Managerial PDF',
        color: '#3b82f6',
        endpoint: '/api/export/pdf',
        contains: ['Team-level risk posture', 'Mitigation effort tracking', 'ATT&CK tactic coverage', 'Resource allocation view'],
    },
    {
        id: 'technical', isPdf: true,
        icon: <ShieldAlert size={22} />,
        name: 'Technical PDF',
        color: '#d946ef',
        endpoint: '/api/export/pdf',
        contains: ['Full IOC lists', 'MITRE ATT&CK technique mappings', 'D3FEND defensive mappings', 'Raw telemetry and indicators'],
    },
    {
        id: 'stix',
        icon: <Database size={22} />,
        name: 'STIX 2.1',
        color: '#00d4ff',
        endpoint: '/api/export/stix',
        contains: ['STIX 2.1 bundle format', 'Compatible with TAXII servers', 'Threat actor objects', 'Indicator & relationship objects'],
    },
    {
        id: 'json',
        icon: <FileJson size={22} />,
        name: 'JSON Export',
        color: '#8b5cf6',
        endpoint: '/api/export/json',
        contains: ['Structured threat records', 'Technique & tactic metadata', 'Risk scores & severities', 'Mitigation recommendations'],
    },
    {
        id: 'csv',
        icon: <FileText size={22} />,
        name: 'CSV Report',
        color: '#10b981',
        endpoint: '/api/export/csv',
        contains: ['Excel-compatible format', 'All threat fields as columns', 'Technique IDs and tactics', 'Timestamps and risk scores'],
    },
    {
        id: 'splunk',
        icon: <Zap size={22} />,
        name: 'Splunk HEC',
        color: '#f97316',
        endpoint: '/api/export/splunk',
        contains: ['Pre-formatted Splunk events', 'HTTP Event Collector ready', 'Indexed threat data', 'Direct SIEM ingestion'],
    },
]

function authHeader() {
    const t = localStorage.getItem('token')
    return t ? { Authorization: `Bearer ${t}` } : {}
}

export default function Reports() {
    const [exporting, setExporting] = useState({})
    const [exported, setExported] = useState({})
    const [exportError, setExportError] = useState({})
    const [threats, setThreats] = useState([])
    const [loadingThreats, setLoadingThreats] = useState(true)

    // Fetch user's analyzed threats to get real IDs
    useEffect(() => {
        axios.get(`${API}/api/users/history`, { headers: authHeader() })
            .then(r => {
                const items = r.data?.items || r.data?.history || r.data || []
                setThreats(Array.isArray(items) ? items : [])
            })
            .catch(() => setThreats([]))
            .finally(() => setLoadingThreats(false))
    }, [])

    const threatIds = threats.map(t => t.id || t.threat_id).filter(Boolean)
    const hasThreats = threatIds.length > 0

    const handleExport = async (fmt) => {
        if (!hasThreats) return

        setExporting(p => ({ ...p, [fmt.id]: true }))
        setExportError(p => ({ ...p, [fmt.id]: null }))

        try {
            const token = localStorage.getItem('token')
            if (!token) throw new Error('Not authenticated')

            // Direct browser navigation for seamless file download, bypassing blob/CORS restrictions
            const url = `${API}/api/export/download/${fmt.id}?token=${token}`
            window.location.href = url

            setExported(p => ({ ...p, [fmt.id]: true }))
            setTimeout(() => setExported(p => ({ ...p, [fmt.id]: false })), 3000)
        } catch (err) {
            setExportError(p => ({ ...p, [fmt.id]: err.message || 'Export failed' }))
        }
        setExporting(p => ({ ...p, [fmt.id]: false }))
    }


    return (
        <div>
            {/* Header */}
            <div style={{ marginBottom: 24 }}>
                <h2 style={{ fontSize: 17, fontWeight: 700, marginBottom: 6 }}>Export Threat Intelligence</h2>
                <p style={{ fontSize: 13, color: '#94a3b8' }}>
                    Export your analyzed threats to STIX 2.1, JSON, CSV, PDF reports, or SIEM-ready formats.
                </p>
            </div>

            {/* Threat count banner */}
            <div style={{
                display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px',
                borderRadius: 10, marginBottom: 24,
                background: hasThreats ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
                border: `1px solid ${hasThreats ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
                color: hasThreats ? '#10b981' : '#ef4444', fontSize: 13,
            }}>
                {loadingThreats
                    ? <><Loader size={14} className="spinning" /> Loading your threats...</>
                    : hasThreats
                        ? <><CheckCircle size={14} /> {threatIds.length} analyzed threat{threatIds.length > 1 ? 's' : ''} ready to export</>
                        : <><AlertCircle size={14} /> No analyzed threats yet — run a Threat Analysis first to generate exportable data</>
                }
            </div>

            {/* Export Cards */}
            <div className="grid-2" style={{ marginBottom: 28 }}>
                {EXPORT_FORMATS.map(fmt => (
                    <div key={fmt.id} className="card" style={{ borderTop: `2px solid ${fmt.color}` }}>
                        {/* Card header */}
                        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, marginBottom: 14 }}>
                            <div style={{
                                width: 44, height: 44, borderRadius: 10,
                                background: `${fmt.color}18`,
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                flexShrink: 0, color: fmt.color,
                            }}>
                                {fmt.icon}
                            </div>
                            <div>
                                <h3 style={{ fontSize: 14, fontWeight: 700, color: '#f0f4ff', marginBottom: 4 }}>
                                    {fmt.name}
                                </h3>
                                {/* What's included */}
                                <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
                                    {fmt.contains.map((item, i) => (
                                        <li key={i} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: '#64748b', marginBottom: 2 }}>
                                            <span style={{ color: fmt.color, fontSize: 8 }}>⬤</span> {item}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        </div>

                        {/* Error */}
                        {exportError[fmt.id] && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#ef4444', marginBottom: 8, padding: '6px 10px', background: 'rgba(239,68,68,0.06)', borderRadius: 6 }}>
                                <AlertCircle size={11} /> {exportError[fmt.id]}
                            </div>
                        )}

                        <button
                            className="btn btn-secondary"
                            style={{ width: '100%', justifyContent: 'center', border: `1px solid ${fmt.color}33`, opacity: (!hasThreats || loadingThreats) ? 0.5 : 1 }}
                            onClick={() => handleExport(fmt)}
                            disabled={exporting[fmt.id] || !hasThreats || loadingThreats}
                        >
                            {exported[fmt.id]
                                ? <><CheckCircle size={14} color="#10b981" /> Downloaded!</>
                                : exporting[fmt.id]
                                    ? <><Loader size={14} className="spinning" /> Exporting...</>
                                    : <><Download size={14} /> Export {fmt.name}</>
                            }
                        </button>
                    </div>
                ))}
            </div>

            {/* SIEM Integration Guide */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title"><Zap size={15} color="#00d4ff" /> SIEM Platform Integration Guide</div>
                </div>
                <div className="grid-3">
                    {[
                        { name: 'Splunk', steps: ['Export Splunk HEC format above', 'Configure HEC token in Splunk', 'POST events to /services/collector', 'Build ATT&CK dashboards'], color: '#f97316' },
                        { name: 'Microsoft Sentinel', steps: ['Export STIX 2.1 bundle', 'Use Logic Apps TAXII connector', 'Map IoCs to Sentinel watchlists', 'Enable ATT&CK analytics rules'], color: '#00d4ff' },
                        { name: 'IBM QRadar', steps: ['Export JSON format', 'Use QRadar REST API /api/data_exports', 'Map fields to QRadar categories', 'Configure offense detection rules'], color: '#7c3aed' },
                    ].map(siem => (
                        <div key={siem.name} style={{ padding: 14, background: 'rgba(255,255,255,0.02)', border: `1px solid ${siem.color}22`, borderRadius: 8 }}>
                            <h4 style={{ fontSize: 13, fontWeight: 700, color: siem.color, marginBottom: 10 }}>{siem.name}</h4>
                            <ol style={{ paddingLeft: 16, listStyleType: 'decimal' }}>
                                {siem.steps.map((s, i) => (
                                    <li key={i} style={{ fontSize: 11.5, color: '#94a3b8', marginBottom: 5, lineHeight: 1.4 }}>{s}</li>
                                ))}
                            </ol>
                        </div>
                    ))}
                </div>
            </div>

            {/* What's in each report info box */}
            <div style={{ marginTop: 20, padding: '14px 18px', borderRadius: 10, background: 'rgba(0,212,255,0.04)', border: '1px solid rgba(0,212,255,0.12)', display: 'flex', gap: 10 }}>
                <Info size={15} color="#00d4ff" style={{ flexShrink: 0, marginTop: 2 }} />
                <p style={{ fontSize: 12, color: '#64748b', margin: 0, lineHeight: 1.6 }}>
                    <strong style={{ color: '#94a3b8' }}>Reports are built from your analyzed threats.</strong> To get more data in your exports, run Threat Analysis on more inputs (text, CVEs, PCAPs) — each analysis adds a record to your export pool. The <strong style={{ color: '#d946ef' }}>Technical PDF</strong> includes the most detail; the <strong style={{ color: '#f43f5e' }}>Executive PDF</strong> is best for sharing with leadership.
                </p>
            </div>
        </div>
    )
}
