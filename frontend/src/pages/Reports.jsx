import { useState } from 'react'
import { Download, FileJson, FileText, Database, Zap, CheckCircle, Briefcase, ShieldAlert, BarChart } from 'lucide-react'
import axios from 'axios'

const API = 'http://localhost:8000'

const EXPORT_FORMATS = [
    { id: 'executive', isPdf: true, icon: <Briefcase size={24} />, name: 'Executive PDF', desc: 'High-level business impact, total threats, and risk posture for C-Suite.', color: '#f43f5e', endpoint: '/api/export/pdf' },
    { id: 'managerial', isPdf: true, icon: <BarChart size={24} />, name: 'Managerial PDF', desc: 'Resource allocation, task workflows, and mitigation effort tracking.', color: '#3b82f6', endpoint: '/api/export/pdf' },
    { id: 'technical', isPdf: true, icon: <ShieldAlert size={24} />, name: 'Technical PDF', desc: 'Detailed IOCs, raw telemetry, and MITRE/D3FEND technique mappings.', color: '#d946ef', endpoint: '/api/export/pdf' },
    { id: 'stix', icon: <Database size={24} />, name: 'STIX 2.1', desc: 'Share threat intelligence in STIX 2.1 JSON bundle format. Compatible with TAXII servers.', color: '#00d4ff', endpoint: '/api/export/stix' },
    { id: 'json', icon: <FileJson size={24} />, name: 'JSON Export', desc: 'Structured JSON format for custom integrations and downstream tooling.', color: '#8b5cf6', endpoint: '/api/export/json' },
    { id: 'csv', icon: <FileText size={24} />, name: 'CSV Report', desc: 'Tabular format for Excel/spreadsheets, including all threat fields.', color: '#10b981', endpoint: '/api/export/csv' },
    { id: 'splunk', icon: <Zap size={24} />, name: 'Splunk HEC', desc: 'Pre-formatted Splunk HTTP Event Collector events for direct ingestion.', color: '#f97316', endpoint: '/api/export/splunk' },
]

export default function Reports() {
    const [exporting, setExporting] = useState({})
    const [exported, setExported] = useState({})

    const handleExport = async (fmt) => {
        setExporting(p => ({ ...p, [fmt.id]: true }))
        try {
            const token = localStorage.getItem('token')
            const headers = token ? { Authorization: `Bearer ${token}` } : {}
            // The original code used fmt.endpoint directly, which is fine.
            // The provided snippet introduced a new path logic, but it seems to be a simplification
            // or a different context. Sticking to the original fmt.endpoint for consistency
            // with the EXPORT_FORMATS definition.
            const path = fmt.endpoint
            const payload = { threat_ids: ['demo-threat-001'], format: fmt.id } // Using 'demo-threat-001' as in original code

            const r = await axios.post(`${API}${path}`, payload, { responseType: 'blob', headers })
            const blob = r.data // The responseType: 'blob' means r.data is already a Blob
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            // Determine file extension based on format ID
            const ext = fmt.isPdf ? 'pdf' : (fmt.id === 'csv' ? 'csv' : 'json')
            a.download = `autoMITRE_${fmt.id}_export.${ext}`
            a.click()
            URL.revokeObjectURL(url)
            setExported(p => ({ ...p, [fmt.id]: true }))
            setTimeout(() => setExported(p => ({ ...p, [fmt.id]: false })), 3000)
        } catch {
            alert('Backend unavailable. Start the API server first.')
        }
        setExporting(p => ({ ...p, [fmt.id]: false }))
    }

    return (
        <div>
            <div style={{ marginBottom: 24 }}>
                <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Export Threat Intelligence</h2>
                <p style={{ fontSize: 13, color: '#94a3b8' }}>Export analyzed threats to STIX 2.1, JSON, CSV, or platform-specific formats for Splunk, QRadar, and Microsoft Sentinel.</p>
            </div>

            <div className="grid-2" style={{ marginBottom: 28 }}>
                {EXPORT_FORMATS.map(fmt => (
                    <div key={fmt.id} className="card" style={{ borderTop: `2px solid ${fmt.color}` }}>
                        <div style={{ display: 'flex', align: 'flex-start', gap: 14, marginBottom: 14 }}>
                            <div style={{ width: 48, height: 48, borderRadius: 10, background: `${fmt.color}18`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, color: fmt.color }}>
                                {fmt.icon}
                            </div>
                            <div>
                                <h3 style={{ fontSize: 15, fontWeight: 700, color: '#f0f4ff', marginBottom: 4 }}>{fmt.name}</h3>
                                <p style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.5 }}>{fmt.desc}</p>
                            </div>
                        </div>
                        <button
                            className="btn btn-secondary"
                            style={{ width: '100%', justifyContent: 'center', border: `1px solid ${fmt.color}33` }}
                            onClick={() => handleExport(fmt)}
                            disabled={exporting[fmt.id]}
                        >
                            {exported[fmt.id] ? <CheckCircle size={15} color="#10b981" /> : exporting[fmt.id] ? <div className="spinner" /> : <Download size={15} />}
                            {exported[fmt.id] ? 'Downloaded!' : exporting[fmt.id] ? 'Exporting...' : `Export ${fmt.name}`}
                        </button>
                    </div>
                ))}
            </div>

            {/* SIEM Integration Guide */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title"><Zap size={16} color="#00d4ff" /> SIEM Platform Integration</div>
                </div>
                <div className="grid-3">
                    {[
                        { name: 'Splunk', steps: ['Download Splunk HEC export', 'Configure HEC token in Settings', 'Import events via HEC endpoint', 'Create ATT&CK dashboards'], color: '#f97316' },
                        { name: 'Microsoft Sentinel', steps: ['Export STIX 2.1 bundle', 'Use Logic Apps connector', 'Map IoCs to Sentinel schema', 'Enable ATT&CK analytics rules'], color: '#00d4ff' },
                        { name: 'IBM QRadar', steps: ['Export JSON format', 'Use QRadar REST API', 'Map to QRadar event categories', 'Configure offense rules'], color: '#7c3aed' },
                    ].map(siem => (
                        <div key={siem.name} style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', border: `1px solid ${siem.color}22`, borderRadius: 8 }}>
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
        </div>
    )
}
