import { motion } from 'framer-motion';

const techGroups = [
  {
    layer: 'Backend',
    color: '#0ea5e9',
    techs: ['Python 3.13', 'FastAPI', 'Uvicorn', 'SQLAlchemy', 'SQLite', 'aiosqlite'],
  },
  {
    layer: 'AI / ML',
    color: '#8b5cf6',
    techs: ['SecureBERT', 'all-mpnet-base-v2', 'ChromaDB (RAG)', 'llama_cpp', 'Groq API', 'MLX / Metal'],
  },
  {
    layer: 'NLP',
    color: '#10b981',
    techs: ['spaCy', 'NLTK', 'Hugging Face', 'scikit-learn', 'Scapy', 'stix2'],
  },
  {
    layer: 'Frontend',
    color: '#f59e0b',
    techs: ['React.js 18', 'Vite', 'TypeScript', 'Recharts', 'Framer Motion', 'Lucide'],
  },
];

export default function TechStackWheel() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-3">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Technology Stack</p>
      <div className="grid grid-cols-2 gap-2 w-full">
        {techGroups.map((group, gi) => (
          <motion.div
            key={group.layer}
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: gi * 0.2, type: 'spring' }}
            className="rounded-xl border p-2"
            style={{ borderColor: `${group.color}40`, backgroundColor: `${group.color}08` }}
          >
            <div className="flex items-center gap-1.5 mb-1.5">
              <motion.div
                animate={{ boxShadow: [`0 0 0 ${group.color}`, `0 0 8px ${group.color}80`, `0 0 0 ${group.color}`] }}
                transition={{ duration: 2, repeat: Infinity, delay: gi * 0.4 }}
                className="w-2 h-2 rounded-full shrink-0"
                style={{ backgroundColor: group.color }}
              />
              <span className="text-[9px] font-bold font-mono" style={{ color: group.color }}>{group.layer}</span>
            </div>
            <div className="flex flex-wrap gap-1">
              {group.techs.map((tech, ti) => (
                <motion.span
                  key={tech}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: gi * 0.2 + ti * 0.07 + 0.3 }}
                  className="text-[7px] font-mono px-1.5 py-0.5 rounded"
                  style={{ color: group.color, backgroundColor: `${group.color}12`, border: `1px solid ${group.color}25` }}
                >
                  {tech}
                </motion.span>
              ))}
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
