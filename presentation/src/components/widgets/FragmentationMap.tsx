import { motion } from 'framer-motion';
import { Shield, Layers, GitBranch, Eye, AlertTriangle, FileText } from 'lucide-react';

const tools = [
  { name: 'Microsoft TMT', color: '#0ea5e9', icon: FileText, x: 15, y: 20, desc: 'Threat Modeling' },
  { name: 'VirusTotal', color: '#f59e0b', icon: Eye, x: 72, y: 10, desc: 'Hash Scanning' },
  { name: 'IriusRisk', color: '#8b5cf6', icon: Shield, x: 80, y: 65, desc: 'Risk Modeling' },
  { name: 'Splunk SIEM', color: '#10b981', icon: Layers, x: 15, y: 72, desc: 'Log Events' },
  { name: 'OWASP Dragon', color: '#ef4444', icon: GitBranch, x: 46, y: 48, desc: 'Web Threats' },
];

export default function FragmentationMap() {
  return (
    <div className="w-full h-full relative flex items-center justify-center">
      <div className="relative w-full h-full">
        {/* Tool nodes */}
        {tools.map((tool, i) => {
          const Icon = tool.icon;
          return (
            <motion.div
              key={tool.name}
              initial={{ opacity: 0, scale: 0 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.2, duration: 0.5, type: 'spring' }}
              className="absolute flex flex-col items-center gap-1"
              style={{ left: `${tool.x}%`, top: `${tool.y}%`, transform: 'translate(-50%,-50%)' }}
            >
              <motion.div
                animate={{ boxShadow: [`0 0 8px ${tool.color}40`, `0 0 20px ${tool.color}80`, `0 0 8px ${tool.color}40`] }}
                transition={{ duration: 2, repeat: Infinity, delay: i * 0.4 }}
                className="w-14 h-14 rounded-xl flex items-center justify-center border"
                style={{ backgroundColor: `${tool.color}15`, borderColor: `${tool.color}50` }}
              >
                <Icon style={{ color: tool.color }} className="w-6 h-6" />
              </motion.div>
              <span className="text-[9px] font-mono text-slate-300 text-center whitespace-nowrap">{tool.name}</span>
              <span className="text-[8px] text-slate-500 text-center">{tool.desc}</span>
            </motion.div>
          );
        })}

        {/* Cross-hatch barrier lines showing NO connection */}
        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
          {[[15,20,46,48],[72,10,46,48],[80,65,46,48],[15,72,46,48]].map(([x1,y1,x2,y2], i) => (
            <motion.line
              key={i}
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="#ef444450"
              strokeWidth="0.5"
              strokeDasharray="2,2"
              initial={{ pathLength: 0, opacity: 0 }}
              animate={{ pathLength: 1, opacity: 1 }}
              transition={{ delay: 1.2 + i * 0.1, duration: 0.6 }}
            />
          ))}
        </svg>

        {/* No connection icon in center */}
        <motion.div
          initial={{ opacity: 0, scale: 0 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 1.8, type: 'spring' }}
          className="absolute"
          style={{ left: '46%', top: '48%', transform: 'translate(-50%,-50%)' }}
        >
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
            className="w-12 h-12 rounded-full border-2 border-dashed border-red-500/60 flex items-center justify-center"
          >
            <AlertTriangle className="w-5 h-5 text-red-500" />
          </motion.div>
          <p className="text-[8px] text-red-400 text-center mt-1 font-mono">NO BRIDGE</p>
        </motion.div>

        {/* Bottom label */}
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 2.2 }}
          className="absolute bottom-2 left-0 right-0 text-center text-[10px] text-slate-500 font-mono"
        >
          5 specialized tools • 0 unified context • endless manual effort
        </motion.p>
      </div>
    </div>
  );
}
