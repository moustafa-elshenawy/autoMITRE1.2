import { motion } from 'framer-motion';
import type { SlideData } from '../data/slides';
import InteractiveArchitecture from './widgets/InteractiveArchitecture';
import LatencyChart from './widgets/LatencyChart';
import AccuracyMetrics from './widgets/AccuracyMetrics';
import ThreatMappingSimulator from './widgets/ThreatMappingSimulator';
import HallucinationGuardrail from './widgets/HallucinationGuardrail';
import HardwareMonitor from './widgets/HardwareMonitor';
import DBSCANClustering from './widgets/DBSCANClustering';
import DataIntakeHub from './widgets/DataIntakeHub';
import DynamicCyberArt from './widgets/DynamicCyberArt';
import SIEMFunnel from './widgets/SIEMFunnel';
import STIXTree from './widgets/STIXTree';
import { Shield } from 'lucide-react';

export default function SlideWrapper({ slide }: { slide: SlideData }) {
  const isTitle = slide.layout === 'title';
  const isSplit = !isTitle; // Force split layout on all content slides

  const renderWidget = () => {
    switch(slide.widget) {
      case 'latency': return <LatencyChart />;
      case 'accuracy': return <AccuracyMetrics />;
      case 'architecture': return <InteractiveArchitecture />;
      case 'simulator': return <ThreatMappingSimulator />;
      case 'guardrail': return <HallucinationGuardrail />;
      case 'hardware': return <HardwareMonitor />;
      case 'dbscan': return <DBSCANClustering />;
      case 'intake': return <DataIntakeHub />;
      case 'siem_funnel': return <SIEMFunnel />;
      case 'stix_tree': return <STIXTree />;
      default: return <DynamicCyberArt seed={slide.id} />;
    }
  };

  // Legendary Title Rendering
  if (isTitle) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.8, filter: 'blur(20px)' }}
        animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
        exit={{ opacity: 0, scale: 1.1, filter: 'blur(20px)' }}
        transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-5xl h-full flex flex-col items-center justify-center text-center relative"
      >
        <motion.div 
          animate={{ scale: [1, 1.05, 1], opacity: [0.3, 0.6, 0.3] }}
          transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
          className="absolute z-0 flex items-center justify-center"
        >
          <Shield className="w-96 h-96 text-cyan-900/40" strokeWidth={0.5} />
        </motion.div>

        <div className="z-10 flex flex-col items-center justify-center w-full">
          <motion.div 
            initial={{ y: 30, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="w-full"
          >
            <h1 
              className="text-7xl font-bold tracking-tighter mb-8 text-slate-50 glitch-text-container" 
              data-text={slide.title}
            >
              {slide.title}
            </h1>
          </motion.div>

          <ul className="space-y-6 w-full max-w-3xl mt-8">
            {slide.content.map((point, idx) => (
              <motion.li 
                key={idx}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.5 + (idx * 0.2) }}
                className="text-2xl text-slate-300 font-light"
              >
                {point}
              </motion.li>
            ))}
          </ul>
        </div>
      </motion.div>
    );
  }

  // Content & Split Slide Rendering
  return (
    <motion.div
      initial={{ opacity: 0, x: 50, filter: 'blur(10px)' }}
      animate={{ opacity: 1, x: 0, filter: 'blur(0px)' }}
      exit={{ opacity: 0, x: -50, filter: 'blur(10px)' }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      className="w-full max-w-7xl h-[80vh] flex flex-col justify-start"
    >
      <div className="mb-10 w-full relative">
        <motion.span 
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="text-emerald-400 font-mono text-sm uppercase tracking-widest mb-3 block"
        >
          {slide.section}
        </motion.span>
        
        <motion.h1 
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="font-bold tracking-tight text-5xl text-slate-50 pb-4 relative"
        >
          {slide.title}
          <div className="absolute bottom-0 left-0 h-[1px] bg-gradient-to-r from-cyan-500 via-emerald-400 to-transparent w-full"></div>
        </motion.h1>
      </div>

      <div className={`flex-grow flex ${isSplit ? 'flex-row gap-12 items-center' : 'flex-col items-center justify-center'} w-full`}>
        <div className={`${isSplit ? 'w-5/12' : 'w-full max-w-4xl'} flex flex-col justify-center h-full`}>
          <ul className="space-y-6 w-full">
            {slide.content.map((point, idx) => {
              const isCode = point.startsWith('-') || point.includes('(');
              return (
                <motion.li 
                  key={idx}
                  initial={{ opacity: 0, x: -30, rotateX: 20 }}
                  animate={{ opacity: 1, x: 0, rotateX: 0 }}
                  whileHover={{ scale: 1.02, x: 10, borderColor: 'rgba(34,211,238,0.5)', backgroundColor: 'rgba(15,23,42,0.8)' }}
                  transition={{ duration: 0.4, delay: 0.4 + (idx * 0.15) }}
                  className="text-xl flex items-start bg-slate-900/40 p-5 rounded-xl border border-slate-800/50 cursor-default transition-colors duration-300 shadow-lg hover:shadow-[0_0_15px_rgba(34,211,238,0.2)] backdrop-blur-sm"
                >
                  <span className="text-cyan-500 mr-4 mt-1.5 opacity-80 shrink-0 drop-shadow-[0_0_5px_rgba(34,211,238,0.8)]">▸</span>
                  <span className={`leading-relaxed ${isCode ? 'font-mono text-cyan-100 text-lg' : 'text-slate-200'}`}>
                    {point}
                  </span>
                </motion.li>
              );
            })}
          </ul>
        </div>
        
        {isSplit && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.6 }}
            className="w-7/12 h-full max-h-[600px] flex items-center justify-center"
          >
            <div className="w-full h-full glass-card flex items-center justify-center relative overflow-hidden shadow-2xl shadow-cyan-900/20 border-cyan-900/30">
              {renderWidget()}
            </div>
          </motion.div>
        )}
      </div>
    </motion.div>
  );
}
