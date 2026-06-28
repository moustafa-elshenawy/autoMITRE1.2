import { motion } from 'framer-motion';

const testCases = [
  { id: 'TC-01', req: 'FR1.1', desc: 'User Login', status: 'PASS' },
  { id: 'TC-02', req: 'FR1.2', desc: 'RBAC Roles', status: 'PASS' },
  { id: 'TC-03', req: 'FR1.3', desc: 'Priv Escalation Block', status: 'PASS' },
  { id: 'TC-04', req: 'FR2.1', desc: 'Multi-fmt Upload', status: 'PASS' },
  { id: 'TC-05', req: 'FR2.2', desc: 'Drag & Drop UI', status: 'PASS' },
  { id: 'TC-06', req: 'FR2.3', desc: 'TMT/IriusRisk Parse', status: 'PASS' },
  { id: 'TC-07', req: 'FR2.4', desc: 'VirusTotal API', status: 'PASS' },
  { id: 'TC-08', req: 'FR3.1', desc: 'AI Text Analysis', status: 'PASS' },
  { id: 'TC-09', req: 'FR3.2', desc: 'Severity Scoring', status: 'PASS' },
  { id: 'TC-10', req: 'FR3.3', desc: 'PCAP Analysis', status: 'PASS' },
  { id: 'TC-11', req: 'FR3.4', desc: 'Log Analysis', status: 'PASS' },
  { id: 'TC-12', req: 'FR4.1', desc: 'ATT&CK Mapping', status: 'PASS' },
  { id: 'TC-13', req: 'FR4.2', desc: 'D3FEND Mapping', status: 'PASS' },
  { id: 'TC-14', req: 'FR5.1', desc: 'Mitigation Gen', status: 'PASS' },
  { id: 'TC-15', req: 'FR6.1', desc: 'Threat Prediction', status: 'PASS' },
  { id: 'TC-16', req: 'FR7.1', desc: 'Dashboard Render', status: 'PASS' },
  { id: 'TC-17', req: 'FR8.1', desc: 'PDF Export', status: 'PASS' },
  { id: 'TC-18', req: 'FR9.1', desc: 'STIX Export', status: 'PASS' },
];

export default function TestMatrix() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-2">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">IEEE 829 Test Case Matrix (37 Total)</p>
      <div className="grid grid-cols-6 gap-1 w-full">
        {testCases.map((tc, i) => (
          <motion.div
            key={tc.id}
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.04, type: 'spring', bounce: 0.4 }}
            className="flex flex-col items-center gap-0.5 p-1 rounded-lg border border-emerald-800/30 bg-emerald-950/20"
            title={`${tc.id}: ${tc.desc}`}
          >
            <span className="text-[6px] font-mono text-slate-500">{tc.id}</span>
            <motion.div
              animate={{ boxShadow: ['0 0 0px #10b981', '0 0 6px #10b98160', '0 0 0px #10b981'] }}
              transition={{ duration: 2, repeat: Infinity, delay: i * 0.1 }}
              className="w-3 h-3 rounded-full bg-emerald-500 flex items-center justify-center"
            >
              <span className="text-[5px] text-white font-bold">✓</span>
            </motion.div>
          </motion.div>
        ))}
        {/* Remaining 19 test cases (simplified) */}
        {Array.from({ length: 19 }).map((_, i) => (
          <motion.div
            key={`extra-${i}`}
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: (testCases.length + i) * 0.04, type: 'spring', bounce: 0.4 }}
            className="flex flex-col items-center gap-0.5 p-1 rounded-lg border border-emerald-800/30 bg-emerald-950/20"
          >
            <span className="text-[6px] font-mono text-slate-500">TC-{testCases.length + i + 1 < 10 ? '0' : ''}{testCases.length + i + 1}</span>
            <div className="w-3 h-3 rounded-full bg-emerald-500 flex items-center justify-center">
              <span className="text-[5px] text-white font-bold">✓</span>
            </div>
          </motion.div>
        ))}
      </div>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
        className="flex items-center gap-3"
      >
        <div className="flex items-center gap-1">
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
          <span className="text-[9px] font-mono font-bold text-emerald-400">37 / 37 PASS (100%)</span>
        </div>
        <span className="text-[8px] text-slate-500 font-mono">|</span>
        <span className="text-[8px] text-slate-500 font-mono">0 Failures • 0 Blocked</span>
      </motion.div>
    </div>
  );
}
