import { motion } from 'framer-motion';
import { Check, X } from 'lucide-react';

const headers = ['AI/NLP', 'Multi-Framework', 'Multi-Format', 'SIEM Export', 'Mitigation Gen', 'Open Source'];
const rows = [
  { name: 'MS TMT',          vals: [false, false, false, false, false, true] },
  { name: 'OWASP Dragon',    vals: [false, false, false, false, false, true] },
  { name: 'IriusRisk',       vals: [false, false, false, true, true, false] },
  { name: 'VirusTotal',      vals: [true, false, false, false, false, false] },
  { name: 'Splunk',          vals: [true, false, false, true, false, false] },
  { name: 'autoMITRE ★',     vals: [true, true, true, true, true, true], highlight: true },
];

export default function ComparisonTable() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-3">Feature Comparison Matrix</p>
      <div className="w-full overflow-auto">
        <table className="w-full text-[9px] font-mono border-collapse">
          <thead>
            <tr>
              <th className="text-left text-slate-400 pb-2 pr-3 font-normal">Tool</th>
              {headers.map(h => (
                <th key={h} className="text-center text-slate-400 pb-2 px-1 font-normal text-[8px]">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, ri) => (
              <motion.tr
                key={row.name}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: ri * 0.2, duration: 0.4 }}
                className={`border-t ${(row as any).highlight ? 'border-amber-500/50' : 'border-slate-800/50'}`}
              >
                <td className={`py-1.5 pr-3 font-bold ${(row as any).highlight ? 'text-amber-400' : 'text-slate-300'}`}>
                  {(row as any).highlight && (
                    <motion.span
                      animate={{ opacity: [1, 0.5, 1] }}
                      transition={{ duration: 1.5, repeat: Infinity }}
                      className="mr-1"
                    >▶</motion.span>
                  )}
                  {row.name}
                </td>
                {row.vals.map((val, vi) => (
                  <td key={vi} className="py-1.5 px-1 text-center">
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ delay: ri * 0.2 + vi * 0.05 + 0.3, type: 'spring' }}
                      className="flex items-center justify-center"
                    >
                      {val ? (
                        <Check className={`w-3 h-3 ${(row as any).highlight ? 'text-amber-400' : 'text-emerald-400'}`} />
                      ) : (
                        <X className="w-3 h-3 text-slate-700" />
                      )}
                    </motion.div>
                  </td>
                ))}
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
