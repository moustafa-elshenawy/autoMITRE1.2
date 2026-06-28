import { motion } from 'framer-motion';

const objectives = [
  { icon: '🚨', title: '1. The Problem', desc: 'SOC workflow limits & alert fatigue', color: '#ef4444' },
  { icon: '🕳️', title: '2. The Gap', desc: 'Where current security tools fail', color: '#f59e0b' },
  { icon: '📐', title: '3. Design', desc: 'Engineering & architecture choices', color: '#10b981' },
  { icon: '🧠', title: '4. AI Engine', desc: 'SecureBERT, RAG, & LLM flow', color: '#8b5cf6' },
  { icon: '📊', title: '5. Results', desc: '96.8% accuracy & IEEE 829', color: '#0ea5e9' },
  { icon: '🚀', title: '6. Conclusion', desc: 'Future work & DBSCAN roadmap', color: '#a855f7' },
];

export default function ObjectivesGrid() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-2">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Presentation Roadmap</p>
      <div className="grid grid-cols-3 gap-2 w-full">
        {objectives.map((obj, i) => (
          <motion.div
            key={obj.title}
            initial={{ opacity: 0, y: 20, scale: 0.8 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ delay: i * 0.15, duration: 0.5, type: 'spring' }}
            whileHover={{ scale: 1.05, y: -2 }}
            className="flex flex-col items-center gap-1.5 p-2.5 rounded-xl border text-center cursor-default"
            style={{ borderColor: `${obj.color}40`, backgroundColor: `${obj.color}0D` }}
          >
            <motion.span
              animate={{ scale: [1, 1.2, 1] }}
              transition={{ duration: 2, repeat: Infinity, delay: i * 0.3 }}
              className="text-2xl"
            >
              {obj.icon}
            </motion.span>
            <p className="text-[9px] font-bold font-mono" style={{ color: obj.color }}>{obj.title}</p>
            <p className="text-[8px] text-slate-500 leading-tight">{obj.desc}</p>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
