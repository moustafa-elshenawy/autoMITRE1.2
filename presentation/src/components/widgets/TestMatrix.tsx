import { motion } from 'framer-motion';

const testCases = [
  { id: 'TC-01', req: 'FR1.1', desc: 'User Login' },
  { id: 'TC-02', req: 'FR1.2', desc: 'RBAC Roles' },
  { id: 'TC-03', req: 'FR1.3', desc: 'Priv Escalation Block' },
  { id: 'TC-04', req: 'FR2.1', desc: 'Multi-fmt Upload' },
  { id: 'TC-05', req: 'FR2.2', desc: 'Drag & Drop UI' },
  { id: 'TC-06', req: 'FR2.3', desc: 'TMT/IriusRisk Parse' },
  { id: 'TC-07', req: 'FR2.4', desc: 'VirusTotal API' },
  { id: 'TC-08', req: 'FR3.1', desc: 'AI Text Analysis' },
  { id: 'TC-09', req: 'FR3.2', desc: 'Severity Scoring' },
  { id: 'TC-10', req: 'FR3.3', desc: 'PCAP Analysis' },
  { id: 'TC-11', req: 'FR3.4', desc: 'Log Analysis' },
  { id: 'TC-12', req: 'FR4.1', desc: 'ATT&CK Mapping' },
  { id: 'TC-13', req: 'FR4.2', desc: 'D3FEND Mapping' },
  { id: 'TC-14', req: 'FR5.1', desc: 'Mitigation Gen' },
  { id: 'TC-15', req: 'FR6.1', desc: 'Threat Prediction' },
  { id: 'TC-16', req: 'FR7.1', desc: 'Dashboard Render' },
  { id: 'TC-17', req: 'FR8.1', desc: 'PDF Export' },
  { id: 'TC-18', req: 'FR9.1', desc: 'STIX Export' },
];

const allTCs = [
  ...testCases,
  ...Array.from({ length: 19 }, (_, i) => ({
    id: `TC-${String(testCases.length + i + 1).padStart(2, '0')}`,
    req: '',
    desc: '',
  })),
];

export default function TestMatrix() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-3">
      <p className="text-[11px] font-mono text-slate-400 uppercase tracking-widest">
        IEEE 829 Test Case Matrix (37 Total)
      </p>

      <div className="grid grid-cols-6 gap-1.5 w-full">
        {allTCs.map((tc, i) => (
          <motion.div
            key={tc.id}
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.03, type: 'spring', bounce: 0.4 }}
            className="flex flex-col items-center gap-1 p-1.5 rounded-lg border border-emerald-800/30 bg-emerald-950/20"
            title={tc.desc ? `${tc.id}: ${tc.desc}` : tc.id}
          >
            <span className="text-[8px] font-mono text-slate-400">{tc.id}</span>
            <motion.div
              animate={{ boxShadow: ['0 0 0px #10b981', '0 0 8px #10b98170', '0 0 0px #10b981'] }}
              transition={{ duration: 2, repeat: Infinity, delay: i * 0.1 }}
              className="w-4 h-4 rounded-full bg-emerald-500 flex items-center justify-center"
            >
              <span className="text-[8px] text-white font-bold">✓</span>
            </motion.div>
          </motion.div>
        ))}
      </div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
        className="flex items-center gap-4"
      >
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full bg-emerald-500" />
          <span className="text-[11px] font-mono font-bold text-emerald-400">37 / 37 PASS (100%)</span>
        </div>
        <span className="text-[10px] text-slate-500 font-mono">|</span>
        <span className="text-[10px] text-slate-500 font-mono">0 Failures • 0 Blocked</span>
      </motion.div>
    </div>
  );
}
