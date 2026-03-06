import { useState, useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { Upload, Search, Hash, FileText, ChevronRight, AlertCircle, CheckCircle, ExternalLink } from 'lucide-react'
import axios from 'axios'

const API = 'http://localhost:8000'

const FRAMEWORK_LABELS = { attack: 'MITRE ATT&CK', defend: 'D3FEND', nist: 'NIST SP 800-53', owasp: 'OWASP' }

function SeverityBadge({ severity }) {
    const map = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low' }
    return <span className={`badge badge-${map[severity] || 'info'}`}>{severity}</span>
}

function RiskMeter({ score }) {
    const pct = (score / 10) * 100
    const color = score >= 9 ? '#ef4444' : score >= 7 ? '#f97316' : score >= 4 ? '#f59e0b' : '#22c55e'
    return (
        <div style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 12 }}>
                <span style={{ color: '#94a3b8' }}>Risk Score</span>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', color, fontWeight: 700, fontSize: 20 }}>{score}/10</span>
            </div>
            <div style={{ height: 10, background: 'rgba(255,255,255,0.06)', borderRadius: 100, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: `linear-gradient(90deg, ${color}88, ${color})`, borderRadius: 100, transition: 'width 0.8s ease', boxShadow: `0 0 10px ${color}80` }} />
            </div>
        </div>
    )
}

// ── VirusTotal Panel ──────────────────────────────────────────────────────────
function formatUnix(ts) {
    if (!ts) return 'Unknown'
    const date = new Date(ts * 1000)
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function VirusTotalPanel({ vt }) {
    if (!vt || !vt.found) return null

    // Safety check for older backend responses without the new fields
    const fileName = vt.meaningful_name || (vt.names && vt.names[0]) || 'Unknown File'
    const sizeStr = vt.file_size ? (vt.file_size / 1024).toFixed(1) + ' KB' : 'Unknown'
    const isMalicious = vt.malicious > 0
    const badgeColor = isMalicious ? '#ef4444' : '#22c55e'

    return (
        <div style={{ marginBottom: 20, padding: 16, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12 }}>
            {/* Header / Score */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ width: 12, height: 12, borderRadius: '50%', background: badgeColor }}></div>
                    <span style={{ fontSize: 14, fontWeight: 600, color: '#f8fafc' }}>VirusTotal Analysis</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <a href={`https://www.virustotal.com/gui/file/${vt.hashes?.sha256}`} target="_blank" rel="noreferrer" className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 11, height: 'auto', display: 'flex', alignItems: 'center' }}>
                        View on VirusTotal <ExternalLink size={12} style={{ marginLeft: 4 }} />
                    </a>
                    <span style={{ fontSize: 12, color: '#94a3b8' }}>Detection: <strong style={{ color: badgeColor, fontSize: 14 }}>{vt.detection_ratio}</strong></span>
                    <span style={{ fontSize: 10, padding: '3px 8px', borderRadius: 4, background: `${badgeColor}20`, color: badgeColor, border: `1px solid ${badgeColor}40`, textTransform: 'uppercase', fontWeight: 700, letterSpacing: 0.5 }}>{vt.verdict}</span>
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(250px, 1fr) 250px', gap: 24, marginBottom: 12 }}>
                {/* File Details */}
                <div>
                    <div style={{ fontSize: 11, color: '#475569', fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>File Details</div>
                    <div style={{ fontSize: 13, color: '#f0f4ff', wordBreak: 'break-all', marginBottom: 2 }}><strong>{fileName}</strong></div>
                    <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>{vt.file_type} {vt.type_extension ? `(.${vt.type_extension})` : ''} · {sizeStr}</div>
                    <div style={{ fontSize: 11, color: '#64748b', fontStyle: 'italic', marginBottom: 6 }}>{vt.trid || vt.magic}</div>

                    {vt.magika && (
                        <div style={{ fontSize: 11, color: '#8b5cf6', marginBottom: 4 }}>
                            <span style={{ opacity: 0.8 }}>Deep Learning Type:</span> <strong>{vt.magika}</strong>
                        </div>
                    )}

                    {vt.signer && <div style={{ fontSize: 12, color: '#0ea5e9', marginTop: 4 }}>✍️ {vt.signer}</div>}

                    {vt.hashes?.sha256 && (
                        <div style={{ marginTop: 8 }}>
                            <div style={{ fontSize: 10, color: '#475569', marginBottom: 2 }}>SHA-256</div>
                            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#94a3b8', background: 'rgba(0,0,0,0.2)', padding: '2px 6px', borderRadius: 4, wordBreak: 'break-all' }}>{vt.hashes.sha256}</div>
                        </div>
                    )}

                    {vt.ssdeep && (
                        <div style={{ marginTop: 8 }}>
                            <div style={{ fontSize: 10, color: '#475569', marginBottom: 2 }}>SSDEEP (Fuzzy Hash)</div>
                            <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: '#64748b', background: 'rgba(0,0,0,0.2)', padding: '2px 6px', borderRadius: 4, wordBreak: 'break-all' }}>{vt.ssdeep}</div>
                        </div>
                    )}
                </div>

                {/* Telemetry & Timestamps */}
                <div>
                    <div style={{ fontSize: 11, color: '#475569', fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>Timeline & Telemetry</div>
                    <div style={{ display: 'grid', gridTemplateColumns: '90px 1fr', gap: '4px 8px', fontSize: 12 }}>
                        {vt.first_seen_itw && <><span style={{ color: '#475569' }}>In the Wild</span> <span style={{ color: '#eab308' }}>{formatUnix(vt.first_seen_itw)}</span></>}
                        <span style={{ color: '#475569' }}>Creation</span> <span style={{ color: '#94a3b8' }}>{formatUnix(vt.creation_date)}</span>
                        <span style={{ color: '#475569' }}>First Seen</span> <span style={{ color: '#94a3b8' }}>{formatUnix(vt.first_seen)}</span>
                        <span style={{ color: '#475569' }}>Last Seen</span> <span style={{ color: '#94a3b8' }}>{formatUnix(vt.last_seen)}</span>
                        <div style={{ height: 4 }}></div><div></div>
                        <span style={{ color: '#475569' }}>Reputation</span> <span style={{ color: vt.reputation < 0 ? '#ef4444' : (vt.reputation > 0 ? '#22c55e' : '#94a3b8'), fontWeight: 600 }}>{vt.reputation || 0}</span>
                        <span style={{ color: '#475569' }}>Submissions</span> <span style={{ color: '#94a3b8' }}>{vt.times_submitted || 0}</span>
                        {vt.unique_sources && <><span style={{ color: '#475569' }}>Unique Sources</span> <span style={{ color: '#94a3b8' }}>{vt.unique_sources}</span></>}
                    </div>
                </div>
            </div>

            {/* Tags and Sandbox hits */}
            {(vt.tags?.length > 0 || vt.sandbox_hits?.length > 0 || vt.yara_hits?.length > 0) && (
                <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 12 }}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {(vt.sandbox_hits || []).map((sb, i) => (
                            <span key={`sb-${i}`} style={{ fontSize: 10, padding: '2px 6px', background: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 4 }}>
                                🦠 {sb}
                            </span>
                        ))}
                        {(vt.yara_hits || []).map((yara, i) => (
                            <span key={`yara-${i}`} style={{ fontSize: 10, padding: '2px 6px', background: 'rgba(245,158,11,0.1)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 4 }}>
                                🎯 YARA: {yara}
                            </span>
                        ))}
                        {(vt.tags || []).map((t, i) => (
                            <span key={`tag-${i}`} style={{ fontSize: 10, padding: '2px 6px', background: 'rgba(255,255,255,0.04)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 4 }}>
                                #{t}
                            </span>
                        ))}
                    </div>
                </div>
            )}
        </div>
    )
}

function ThreatResultPanel({ result }) {
    const [activeTab, setActiveTab] = useState('attack')
    if (!result) return null
    const { risk_score, attack_techniques, defend_countermeasures, nist_controls, owasp_items, mitigations, entities } = result

    // If it's a direct hash lookup, only show the VirusTotal panel
    if (result.input_type === 'hash') {
        return (
            <div style={{ marginTop: 20 }}>
                {result.raw_indicators?.virustotal ? (
                    <VirusTotalPanel vt={result.raw_indicators.virustotal} />
                ) : (
                    <div className="card alert alert-warning">
                        No VirusTotal data available for this hash.
                    </div>
                )}
            </div>
        )
    }

    return (
        <div className="card" style={{ marginTop: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                        <CheckCircle size={18} color="#10b981" />
                        <h3 style={{ fontSize: 16, fontWeight: 700 }}>{result.title}</h3>
                    </div>
                    <p style={{ fontSize: 12, color: '#94a3b8', maxWidth: 600 }}>{result.description?.slice(0, 200)}</p>
                </div>
                <SeverityBadge severity={risk_score?.severity} />
            </div>

            <RiskMeter score={risk_score?.score || 0} />

            {risk_score?.business_impact && (
                <div className="alert alert-warning" style={{ marginBottom: 16 }}>
                    <AlertCircle size={16} style={{ flexShrink: 0 }} />
                    <span style={{ fontSize: 12 }}>{risk_score.business_impact}</span>
                </div>
            )}

            {/* Entities */}
            {entities?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 11, color: '#475569', marginBottom: 6, fontWeight: 600, letterSpacing: '0.8px', textTransform: 'uppercase' }}>Extracted Indicators</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {entities.map((e, i) => (
                            <span key={i} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, padding: '2px 8px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 4, color: '#94a3b8' }}>
                                <span style={{ color: '#00d4ff', marginRight: 4 }}>[{e.type}]</span>{e.value}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* VirusTotal Panel */}
            {result.raw_indicators?.virustotal && (
                <VirusTotalPanel vt={result.raw_indicators.virustotal} />
            )}

            {/* Framework Tabs */}
            <div className="tabs" style={{ marginBottom: 16 }}>
                {['attack', 'defend', 'nist', 'owasp', 'mitigations'].map(t => (
                    <button key={t} className={`tab ${activeTab === t ? 'active' : ''}`} onClick={() => setActiveTab(t)}>
                        {t === 'attack' ? `ATT&CK (${attack_techniques?.length || 0})` :
                            t === 'defend' ? `D3FEND (${defend_countermeasures?.length || 0})` :
                                t === 'nist' ? `NIST (${nist_controls?.length || 0})` :
                                    t === 'owasp' ? `OWASP (${owasp_items?.length || 0})` :
                                        `Mitigations (${mitigations?.length || 0})`}
                    </button>
                ))}
            </div>

            {activeTab === 'attack' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {attack_techniques?.map(t => (
                        <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', background: 'rgba(0,212,255,0.04)', borderRadius: 6, border: '1px solid rgba(0,212,255,0.1)' }}>
                            <span className="badge badge-attack">{t.id}</span>
                            <div style={{ flex: 1 }}>
                                <div style={{ fontSize: 13, fontWeight: 600, color: '#f0f4ff' }}>{t.name}</div>
                                <div style={{ fontSize: 11, color: '#94a3b8' }}>{t.tactic}</div>
                            </div>
                            <div style={{ fontSize: 11, color: t.confidence > 0.7 ? '#10b981' : '#f59e0b' }}>
                                {Math.round(t.confidence * 100)}% confidence
                            </div>
                            <a href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}`} target="_blank" rel="noreferrer" style={{ color: '#00d4ff' }}>
                                <ExternalLink size={12} />
                            </a>
                        </div>
                    ))}
                </div>
            )}

            {activeTab === 'defend' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {defend_countermeasures?.map(c => (
                        <div key={c.id} style={{ padding: '10px 12px', background: 'rgba(16,185,129,0.04)', borderRadius: 6, border: '1px solid rgba(16,185,129,0.1)' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                <span className="badge badge-defend">{c.id}</span>
                                <span style={{ fontSize: 13, fontWeight: 600 }}>{c.name}</span>
                                <span style={{ fontSize: 10, color: '#34d399', marginLeft: 'auto' }}>{c.category}</span>
                            </div>
                            <p style={{ fontSize: 12, color: '#94a3b8' }}>{c.description}</p>
                        </div>
                    ))}
                </div>
            )}

            {activeTab === 'nist' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {nist_controls?.map(c => (
                        <div key={c.id} style={{ padding: '10px 12px', background: 'rgba(124,58,237,0.04)', borderRadius: 6, border: '1px solid rgba(124,58,237,0.1)' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                <span className="badge badge-nist">{c.id}</span>
                                <span style={{ fontSize: 13, fontWeight: 600 }}>{c.name}</span>
                                <span style={{ fontSize: 10, color: '#94a3b8', marginLeft: 'auto' }}>{c.family}</span>
                            </div>
                            <p style={{ fontSize: 12, color: '#94a3b8' }}>{c.description}</p>
                        </div>
                    ))}
                </div>
            )}

            {activeTab === 'owasp' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {owasp_items?.map(o => (
                        <div key={o.id} style={{ padding: '10px 12px', background: 'rgba(249,115,22,0.04)', borderRadius: 6, border: '1px solid rgba(249,115,22,0.1)' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                <span className="badge badge-owasp">{o.id}</span>
                                <span style={{ fontSize: 13, fontWeight: 600 }}>{o.name}</span>
                                <span style={{ fontSize: 10, color: '#fb923c', marginLeft: 'auto', textTransform: 'uppercase' }}>{o.type}</span>
                            </div>
                            <p style={{ fontSize: 12, color: '#94a3b8' }}>{o.description}</p>
                        </div>
                    ))}
                </div>
            )}

            {activeTab === 'mitigations' && (
                <div>
                    {mitigations?.map((m, i) => (
                        <div key={i} className="mitigation-step">
                            <div className="mitigation-number">{i + 1}</div>
                            <div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                    <span style={{ fontSize: 13, fontWeight: 600, color: '#f0f4ff' }}>{m.title}</span>
                                    <span className={`badge badge-${m.priority === 'Critical' ? 'critical' : m.priority === 'High' ? 'high' : 'medium'}`} style={{ fontSize: 10 }}>{m.priority}</span>
                                    <span style={{ fontSize: 10, color: '#475569', marginLeft: 'auto' }}>Effort: {m.effort}</span>
                                </div>
                                <p style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.5 }}>{m.description}</p>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    )
}

export default function ThreatAnalysis() {
    const [tab, setTab] = useState('text')
    const [text, setText] = useState('')
    const [hash, setHash] = useState('')
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null)
    const [error, setError] = useState(null)

    const analyze = async (content, endpoint) => {
        setLoading(true); setError(null); setResult(null)
        try {
            const token = localStorage.getItem('token')
            const headers = token ? { Authorization: `Bearer ${token}` } : {}
            const r = await axios.post(`${API}${endpoint}`, content, { headers })
            if (r.data.success) setResult(r.data.threat_result)
            else setError(r.data.error || 'Analysis failed')
        } catch (e) {
            setError(e.response?.data?.detail || 'Backend unavailable — check that the API server is running on port 8000')
        }
        setLoading(false)
    }

    const [useV2, setUseV2] = useState(false)

    const analyzeText = () => analyze(
        useV2 ? { type: 'text', content: text } : { text },
        useV2 ? '/api/v2/analyze' : '/api/analyze/text'
    )
    const analyzeHash = () => analyze({ hash, hash_type: 'sha256' }, '/api/analyze/hash')

    const onDrop = useCallback(async (files) => {
        if (!files[0]) return
        const fd = new FormData()
        fd.append('file', files[0])
        setLoading(true); setError(null); setResult(null)
        try {
            const token = localStorage.getItem('token')
            const headers = token ? { Authorization: `Bearer ${token}`, 'Content-Type': 'multipart/form-data' } : { 'Content-Type': 'multipart/form-data' }
            const r = await axios.post(`${API}/api/analyze/file`, fd, { headers })
            if (r.data.success) setResult(r.data.threat_result)
            else setError(r.data.error)
        } catch (e) {
            setError('Backend unavailable — start the API server first')
        }
        setLoading(false)
    }, [])

    const { getRootProps, getInputProps, isDragActive } = useDropzone({
        onDrop,
        accept: {
            'text/*': ['.txt', '.log', '.csv'],
            'application/json': ['.json'],
            'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng']
        }
    })

    const exampleText = "Detected ransomware activity: SQL injection attempt on login portal, Mimikatz credential dumping observed, PowerShell execution with base64-encoded payload, lateral movement via RDP to internal servers, C2 beacon to evil-c2.attacker.com on port 443, data exfiltration detected. CVE-2024-1234 exploit attempted."

    return (
        <div>
            <div className="page-header" style={{ marginBottom: 16 }}>
                <h1>Threat Analysis</h1>
                <p>Submit text, file, or hash for AI-powered threat detection and framework mapping</p>
            </div>

            <div className="card">
                <div className="tabs" style={{ marginBottom: 20 }}>
                    {[['text', <FileText size={14} />, 'Text / Description'], ['hash', <Hash size={14} />, 'Malware Hash'], ['file', <Upload size={14} />, 'File Upload']].map(([id, icon, label]) => (
                        <button key={id} className={`tab ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)} style={{ display: 'flex', alignItems: 'center', gap: 5, justifyContent: 'center' }}>
                            {icon}{label}
                        </button>
                    ))}
                </div>

                {tab === 'text' && (
                    <div>
                        <div className="form-group">
                            <label className="form-label">Threat Description / Log / Event</label>
                            <textarea className="form-input" style={{ minHeight: 140 }} placeholder="Paste threat description, log entries, IOCs, incident report..." value={text} onChange={e => setText(e.target.value)} />
                        </div>
                        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                            <button className="btn btn-primary btn-lg" onClick={analyzeText} disabled={!text.trim() || loading}>
                                {loading ? <div className="spinner" /> : <Search size={16} />}
                                {loading ? 'Analyzing...' : 'Analyze Threat'}
                            </button>
                            <button className="btn btn-secondary" onClick={() => setText(exampleText)}>Load Example</button>
                        </div>
                        <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', width: 'fit-content' }}>
                            <input
                                type="checkbox"
                                id="v2-toggle"
                                checked={useV2}
                                onChange={e => setUseV2(e.target.checked)}
                                style={{ accentColor: '#00d4ff', width: 16, height: 16, cursor: 'pointer' }}
                            />
                            <label htmlFor="v2-toggle" style={{ fontSize: 13, color: '#e2e8f0', cursor: 'pointer', userSelect: 'none' }}>
                                Use <strong>Custom 6-Model AI Pipeline</strong> (v2)
                            </label>
                        </div>
                    </div>
                )}

                {tab === 'hash' && (
                    <div>
                        <div className="form-group">
                            <label className="form-label">Malware Hash (MD5 / SHA1 / SHA256)</label>
                            <input className="form-input" style={{ fontFamily: 'JetBrains Mono, monospace' }} placeholder="e.g. a3b2c1d4e5f6... or paste a 32/40/64-char hash" value={hash} onChange={e => setHash(e.target.value)} />
                        </div>
                        <div className="alert alert-info">
                            <AlertCircle size={14} style={{ flexShrink: 0 }} />
                            <span style={{ fontSize: 12 }}>VirusTotal live integration. Make sure VIRUSTOTAL_API_KEY is configured in the backend .env file. Error messages will be returned on failure.</span>
                        </div>
                        <button className="btn btn-primary" onClick={analyzeHash} disabled={!hash.trim() || loading}>
                            {loading ? <div className="spinner" /> : <Search size={16} />}
                            {loading ? 'Looking up...' : 'Lookup & Analyze'}
                        </button>
                    </div>
                )}

                {tab === 'file' && (
                    <div>
                        <div {...getRootProps()} className={`upload-zone ${isDragActive ? 'drag-active' : ''}`}>
                            <input {...getInputProps()} />
                            <Upload className="upload-zone-icon" />
                            <div className="upload-zone-title">Drop files here or click to browse</div>
                            <div className="upload-zone-sub">Supports: JSON, STIX 2.1, CSV, text logs, PCAP/PCAPNG network captures</div>
                        </div>
                        {loading && <div style={{ textAlign: 'center', padding: 20 }}><div className="spinner" style={{ margin: '0 auto' }} /></div>}
                    </div>
                )}

                {error && (
                    <div className="alert alert-critical" style={{ marginTop: 16 }}>
                        <AlertCircle size={16} style={{ flexShrink: 0 }} />
                        <div><strong>Error:</strong> {error}</div>
                    </div>
                )}
            </div>

            <ThreatResultPanel result={result} />
        </div>
    )
}
