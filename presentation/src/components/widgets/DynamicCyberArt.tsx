import { motion } from 'framer-motion';
import { Activity, Radio, Cpu, Network } from 'lucide-react';

interface DynamicCyberArtProps {
  seed: number;
}

export default function DynamicCyberArt({ seed }: DynamicCyberArtProps) {
  const artType = seed % 4;

  const renderArt = () => {
    switch (artType) {
      case 0:
        return <RadarSweep />;
      case 1:
        return <NetworkGraph seed={seed} />;
      case 2:
        return <SineWaves />;
      case 3:
        return <HexagonCore />;
      default:
        return <RadarSweep />;
    }
  };

  return (
    <div className="w-full h-full flex flex-col items-center justify-center relative overflow-hidden bg-slate-900/40 rounded-xl">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(34,211,238,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(34,211,238,0.03)_1px,transparent_1px)] bg-[size:30px_30px]"></div>
      {renderArt()}
      <div className="absolute bottom-4 right-4 font-mono text-xs text-cyan-500/50 flex items-center gap-2">
        <Activity className="w-3 h-3" />
        VISUALIZATION_ID: {seed.toString(16).toUpperCase().padStart(4, '0')}
      </div>
    </div>
  );
}

function RadarSweep() {
  return (
    <div className="relative w-64 h-64 border-2 border-emerald-500/30 rounded-full flex items-center justify-center">
      <div className="absolute inset-0 rounded-full border border-emerald-500/20 scale-50"></div>
      <div className="absolute inset-0 rounded-full border border-emerald-500/10 scale-75"></div>
      <div className="absolute w-full h-[1px] bg-emerald-500/30"></div>
      <div className="absolute h-full w-[1px] bg-emerald-500/30"></div>
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
        className="absolute inset-0 rounded-full"
        style={{
          background: 'conic-gradient(from 0deg, transparent 70%, rgba(52, 211, 153, 0.4) 100%)',
        }}
      />
      <Radio className="w-6 h-6 text-emerald-400 opacity-50 absolute" />
      <motion.div 
        animate={{ opacity: [0, 1, 0], scale: [0.8, 1.2, 0.8] }}
        transition={{ duration: 2, repeat: Infinity, delay: 1 }}
        className="absolute top-12 left-16 w-3 h-3 bg-emerald-400 rounded-full shadow-[0_0_10px_#34d399]"
      />
      <motion.div 
        animate={{ opacity: [0, 1, 0], scale: [0.8, 1.2, 0.8] }}
        transition={{ duration: 3, repeat: Infinity, delay: 0.5 }}
        className="absolute bottom-16 right-20 w-2 h-2 bg-rose-400 rounded-full shadow-[0_0_10px_#f43f5e]"
      />
    </div>
  );
}

function NetworkGraph({ seed }: { seed: number }) {
  const nodes = Array.from({ length: 8 }).map((_, i) => ({
    id: i,
    x: Math.sin(i + seed) * 100,
    y: Math.cos(i * seed) * 100,
  }));

  return (
    <div className="relative w-full h-full flex items-center justify-center">
      <Network className="w-16 h-16 text-cyan-500/20 absolute" />
      {nodes.map((node, i) => (
        <motion.div
          key={node.id}
          animate={{
            x: [node.x, node.x + 20, node.x],
            y: [node.y, node.y - 20, node.y],
          }}
          transition={{ duration: 4 + (i % 3), repeat: Infinity, ease: "easeInOut" }}
          className="absolute w-4 h-4 bg-cyan-400 rounded-full shadow-[0_0_15px_#22d3ee]"
          style={{ left: `calc(50% + ${node.x}px)`, top: `calc(50% + ${node.y}px)` }}
        >
          {i % 2 === 0 && (
            <motion.div 
              animate={{ opacity: [0.2, 0.8, 0.2] }}
              transition={{ duration: 2, repeat: Infinity }}
              className="absolute -inset-8 border border-cyan-400/30 rounded-full"
            />
          )}
        </motion.div>
      ))}
    </div>
  );
}

function SineWaves() {
  return (
    <div className="relative w-full h-64 flex flex-col items-center justify-center gap-4 overflow-hidden">
      {[1, 2, 3].map((i) => (
        <motion.div
          key={i}
          animate={{ x: [-1000, 0] }}
          transition={{ duration: 10 / i, repeat: Infinity, ease: "linear" }}
          className="w-[200%] h-12 flex"
          style={{ opacity: 1 - i * 0.2 }}
        >
          {Array.from({ length: 20 }).map((_, j) => (
            <svg key={j} className={`w-32 h-full text-${i === 1 ? 'rose' : i === 2 ? 'purple' : 'indigo'}-500`} viewBox="0 0 100 50" preserveAspectRatio="none">
              <path d="M0,25 Q25,0 50,25 T100,25" fill="none" stroke="currentColor" strokeWidth="3" />
            </svg>
          ))}
        </motion.div>
      ))}
    </div>
  );
}

function HexagonCore() {
  return (
    <div className="relative w-64 h-64 flex items-center justify-center">
      <Cpu className="w-10 h-10 text-indigo-400 absolute z-10" />
      {[1, 2, 3].map((i) => (
        <motion.div
          key={i}
          animate={{ rotate: i % 2 === 0 ? 360 : -360 }}
          transition={{ duration: 10 + i * 5, repeat: Infinity, ease: "linear" }}
          className="absolute border-2 border-indigo-500/40 shadow-[0_0_15px_rgba(99,102,241,0.2)]"
          style={{
            width: `${i * 80}px`,
            height: `${i * 80}px`,
            clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)'
          }}
        />
      ))}
    </div>
  );
}
