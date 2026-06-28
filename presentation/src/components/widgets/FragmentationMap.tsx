import { motion } from 'framer-motion';
import { Activity, Layers, GitBranch, Eye, AlertTriangle, FileText } from 'lucide-react';

// Pentagon positions (cx, cy) around center (250, 200), r=130
const tools = [
  { name: 'Microsoft TMT', desc: 'Threat Modeling',   color: '#0ea5e9', Icon: FileText, cx: 250, cy: 60  },
  { name: 'VirusTotal',    desc: 'Hash Scanning',     color: '#f59e0b', Icon: Eye,      cx: 390, cy: 155 },
  { name: 'Network Logs',  desc: 'PCAP Traffic',      color: '#8b5cf6', Icon: Activity, cx: 340, cy: 315 },
  { name: 'Splunk SIEM',   desc: 'Log Events',        color: '#10b981', Icon: Layers,   cx: 160, cy: 315 },
  { name: 'OWASP Dragon',  desc: 'Web Threats',       color: '#ef4444', Icon: GitBranch,cx: 110, cy: 155 },
];

const CX = 250, CY = 200;

export default function FragmentationMap() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center gap-1">
      <svg viewBox="0 0 500 390" className="w-full h-full" style={{ overflow: 'visible' }}>
        {/* Dashed lines from each tool to center */}
        {tools.map((t, i) => (
          <motion.line
            key={i}
            x1={t.cx} y1={t.cy} x2={CX} y2={CY}
            stroke="#ef444455"
            strokeWidth="1"
            strokeDasharray="4,3"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 1 }}
            transition={{ delay: 1.0 + i * 0.1, duration: 0.5 }}
          />
        ))}

        {/* Tool nodes */}
        {tools.map((t, i) => {
          const Icon = t.Icon;
          return (
            <motion.g
              key={t.name}
              initial={{ opacity: 0, scale: 0 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.18, duration: 0.45, type: 'spring' }}
              style={{ transformOrigin: `${t.cx}px ${t.cy}px` }}
            >
              {/* Glow ring */}
              <motion.circle
                cx={t.cx} cy={t.cy} r={28}
                fill={`${t.color}18`}
                stroke={`${t.color}60`}
                strokeWidth="1"
                animate={{ opacity: [0.6, 1, 0.6] }}
                transition={{ duration: 2, repeat: Infinity, delay: i * 0.3 }}
              />
              {/* Icon background */}
              <circle cx={t.cx} cy={t.cy} r={20} fill={`${t.color}25`} stroke={`${t.color}80`} strokeWidth="1.2" />
              {/* Name label */}
              <text x={t.cx} y={t.cy + 38} textAnchor="middle" fontSize="9" fill="#e2e8f0" fontFamily="monospace" fontWeight="bold">{t.name}</text>
              <text x={t.cx} y={t.cy + 49} textAnchor="middle" fontSize="7.5" fill="#64748b" fontFamily="monospace">{t.desc}</text>
              {/* Lucide icon rendered via foreignObject */}
              <foreignObject x={t.cx - 11} y={t.cy - 11} width={22} height={22} style={{ overflow: 'visible' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '22px', height: '22px' }}>
                  <Icon style={{ color: t.color, width: '14px', height: '14px' }} />
                </div>
              </foreignObject>
            </motion.g>
          );
        })}

        {/* NO BRIDGE center badge */}
        <motion.g
          initial={{ opacity: 0, scale: 0 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 1.6, type: 'spring' }}
          style={{ transformOrigin: `${CX}px ${CY}px` }}
        >
          <motion.circle
            cx={CX} cy={CY} r={24}
            fill="#ef444415"
            stroke="#ef444466"
            strokeWidth="1.5"
            strokeDasharray="4,3"
            animate={{ rotate: 360 }}
            style={{ transformOrigin: `${CX}px ${CY}px` }}
            transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
          />
          <foreignObject x={CX - 10} y={CY - 10} width={20} height={20}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '20px', height: '20px' }}>
              <AlertTriangle style={{ color: '#ef4444', width: '13px', height: '13px' }} />
            </div>
          </foreignObject>
          <text x={CX} y={CY + 34} textAnchor="middle" fontSize="8" fill="#ef4444" fontFamily="monospace" fontWeight="bold">NO BRIDGE</text>
        </motion.g>

        {/* Bottom label */}
        <motion.text
          x={250} y={378}
          textAnchor="middle" fontSize="8" fill="#475569" fontFamily="monospace"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2.2 }}
        >
          5 specialized tools • 0 unified context • endless manual effort
        </motion.text>
      </svg>
    </div>
  );
}


