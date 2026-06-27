import { motion } from 'framer-motion';
import { 
  Target, Globe, AlertTriangle, BrainCircuit,
  Server, Lock, Rocket, ShieldCheck, FileJson, CheckCircle, Lightbulb, Database, Code, Shield, Network
} from 'lucide-react';

interface WidgetProps {
  id: string;
}

export default function BespokeWidgetFactory({ id }: WidgetProps) {
  switch (id) {
    case 'agenda': return <AgendaWidget />;
    case 'threat_landscape': return <ThreatLandscapeWidget />;
    case 'alert_fatigue': return <AlertFatigueWidget />;
    case 'tool_fragmentation': return <ToolFragmentationWidget />;
    case 'research_problem': return <ResearchProblemWidget />;
    case 'objectives': return <ObjectivesWidget />;
    case 'mapping_integration': return <MappingIntegrationWidget />;
    case 'state_of_art': return <StateOfArtWidget />;
    case 'comparison_matrix': return <ComparisonMatrixWidget />;
    case 'generic_ai': return <GenericAIProblemWidget />;
    case 'contribution': return <UniqueContributionWidget />;
    case 'cyber_frameworks': return <FoundationalFrameworksWidget />;
    case 'compliance': return <ComplianceStandardsWidget />;
    case 'ai_ml_stack': return <AIMLStackWidget />;
    case 'tech_stack': return <PrimaryTechStackWidget />;
    case 'auto_mitigation': return <AutoMitigationWidget />;
    case 'predictive_forecast': return <PredictiveForecastingWidget />;
    case 'dashboard_features': return <InteractiveDashboardWidget />;
    case 'live_export': return <LiveExportWidget />;
    case 'validation_results': return <ValidationResultsWidget />;
    case 'key_findings': return <KeyFindingsWidget />;
    case 'limitations': return <AcknowledgedLimitationsWidget />;
    case 'real_world_value': return <RealWorldValueWidget />;
    case 'conclusion': return <ConclusionWidget />;
    default: return <div className="text-white">Widget not found: {id}</div>;
  }
}

// 1. Agenda
function AgendaWidget() {
  return (
    <div className="relative flex flex-col items-center justify-center h-full w-full">
      <div className="absolute left-1/2 top-1/4 bottom-1/4 w-1 bg-cyan-500/20 rounded-full" />
      {[0, 1, 2, 3].map((i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.3, duration: 0.5 }}
          className="relative w-8 h-8 bg-cyan-500 rounded-full mb-8 last:mb-0 shadow-[0_0_15px_#06b6d4] flex items-center justify-center z-10"
        >
          <div className="w-3 h-3 bg-white rounded-full animate-pulse" />
        </motion.div>
      ))}
    </div>
  );
}

// 2. Threat Landscape
function ThreatLandscapeWidget() {
  return (
    <div className="relative w-64 h-64 flex items-center justify-center">
      <Globe className="w-24 h-24 text-blue-500/30 animate-[spin_10s_linear_infinite]" />
      {[1, 2, 3, 4, 5].map((i) => (
        <motion.div
          key={i}
          animate={{
            scale: [0, 1.5],
            opacity: [1, 0]
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            delay: i * 0.4
          }}
          className="absolute w-8 h-8 bg-red-500/40 rounded-full"
          style={{
            top: `${Math.random() * 80 + 10}%`,
            left: `${Math.random() * 80 + 10}%`
          }}
        />
      ))}
    </div>
  );
}

// 3. Alert Fatigue
function AlertFatigueWidget() {
  return (
    <div className="relative flex flex-col items-center justify-end h-64 w-48 border-b-4 border-red-500/50 overflow-hidden pb-4">
      {[...Array(15)].map((_, i) => (
        <motion.div
          key={i}
          initial={{ y: -200, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.5, delay: i * 0.1, repeat: Infinity, repeatDelay: 1.5 }}
          className="w-full h-4 bg-red-500/80 rounded mb-1 flex items-center justify-center shadow-[0_0_10px_#ef4444]"
        >
          <AlertTriangle className="w-3 h-3 text-white" />
        </motion.div>
      ))}
      <div className="absolute inset-0 bg-gradient-to-t from-red-500/20 to-transparent" />
    </div>
  );
}

// 4. Tool Fragmentation
function ToolFragmentationWidget() {
  return (
    <div className="relative w-full h-full flex flex-wrap gap-4 items-center justify-center">
      {[Shield, Server, Database, Code, Network].map((Icon, i) => (
        <motion.div
          key={i}
          animate={{
            x: [0, (Math.random() - 0.5) * 50, 0],
            y: [0, (Math.random() - 0.5) * 50, 0],
            rotate: [0, 180, 360]
          }}
          transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
          className="p-4 bg-slate-800 rounded-xl border border-slate-700 text-slate-400"
        >
          <Icon className="w-8 h-8" />
        </motion.div>
      ))}
    </div>
  );
}

// 5. Research Problem
function ResearchProblemWidget() {
  return (
    <div className="relative flex items-center justify-between w-64 h-32">
      <div className="w-20 h-20 bg-blue-500/20 rounded-lg border border-blue-500 flex items-center justify-center text-xs text-blue-400 z-10">STATIC</div>
      <motion.div
        animate={{ scaleX: [0, 1], opacity: [0, 1, 0] }}
        transition={{ duration: 2, repeat: Infinity }}
        className="h-1 bg-red-500 shadow-[0_0_10px_#ef4444] absolute left-20 right-20 origin-left"
      />
      <div className="w-20 h-20 bg-emerald-500/20 rounded-lg border border-emerald-500 flex items-center justify-center text-xs text-emerald-400 z-10">DYNAMIC</div>
    </div>
  );
}

// 6. Objectives
function ObjectivesWidget() {
  return (
    <div className="relative flex items-center justify-center w-64 h-64">
      <Target className="w-24 h-24 text-emerald-500 opacity-50" />
      {[1, 2, 3].map((i) => (
        <motion.div
          key={i}
          initial={{ x: -100, y: -100, opacity: 0 }}
          animate={{ x: 0, y: 0, opacity: 1 }}
          transition={{ delay: i * 0.5, type: 'spring' }}
          className="absolute w-4 h-4 bg-emerald-400 rounded-full shadow-[0_0_15px_#34d399]"
        />
      ))}
    </div>
  );
}

// 7. Mapping Integration
function MappingIntegrationWidget() {
  return (
    <div className="relative w-64 h-64 flex flex-col items-center justify-center gap-8">
      <div className="w-32 h-12 bg-slate-800 rounded-lg border border-cyan-500 flex items-center justify-center text-cyan-400 font-mono text-sm">TELEMETRY</div>
      <motion.div
        animate={{ scaleY: [0, 1] }}
        transition={{ duration: 1, repeat: Infinity }}
        className="w-1 h-8 bg-cyan-500 shadow-[0_0_10px_#06b6d4] origin-top"
      />
      <div className="flex gap-4">
        <div className="w-24 h-12 bg-slate-800 rounded-lg border border-emerald-500 flex items-center justify-center text-emerald-400 font-mono text-xs">MITRE</div>
        <div className="w-24 h-12 bg-slate-800 rounded-lg border border-indigo-500 flex items-center justify-center text-indigo-400 font-mono text-xs">NIST</div>
      </div>
    </div>
  );
}

// 8. State of Art
function StateOfArtWidget() {
  return (
    <div className="flex gap-4">
      {[1, 2, 3].map((i) => (
        <motion.div
          key={i}
          animate={{ y: [0, -10, 0] }}
          transition={{ duration: 2, delay: i * 0.2, repeat: Infinity }}
          className="w-16 h-48 bg-slate-800 rounded border border-slate-700 flex items-end p-2"
        >
          <div className={`w-full h-${i * 12} bg-indigo-500/50 rounded`} />
        </motion.div>
      ))}
    </div>
  );
}

// 9. Comparison Matrix
function ComparisonMatrixWidget() {
  return (
    <div className="relative w-48 h-48 border border-cyan-500/30 rounded-full flex items-center justify-center">
      <div className="absolute w-full h-px bg-cyan-500/30" />
      <div className="absolute h-full w-px bg-cyan-500/30" />
      <div className="absolute w-full h-px bg-cyan-500/30 rotate-45" />
      <div className="absolute w-full h-px bg-cyan-500/30 -rotate-45" />
      <motion.svg viewBox="0 0 100 100" className="absolute inset-0 text-emerald-500 fill-emerald-500/20 stroke-emerald-500 stroke-2">
        <motion.polygon
          animate={{
            points: [
              "50,10 90,50 50,90 10,50",
              "50,20 80,50 50,80 20,50",
              "50,10 90,50 50,90 10,50"
            ]
          }}
          transition={{ duration: 3, repeat: Infinity }}
        />
      </motion.svg>
    </div>
  );
}

// 10. Generic AI Problem
function GenericAIProblemWidget() {
  return (
    <div className="relative flex items-center justify-center">
      <BrainCircuit className="w-32 h-32 text-indigo-500/50" />
      <motion.div
        animate={{ opacity: [0, 1, 0], scale: [0.8, 1.2, 0.8] }}
        transition={{ duration: 0.5, repeat: Infinity, repeatType: "mirror" }}
        className="absolute top-0 right-0 p-2 bg-red-500 text-white text-xs font-bold rounded shadow-[0_0_20px_#ef4444]"
      >
        HALLUCINATION
      </motion.div>
    </div>
  );
}

// 11. Contribution
function UniqueContributionWidget() {
  return (
    <motion.div
      initial={{ scale: 0 }}
      animate={{ scale: 1, rotate: 360 }}
      transition={{ duration: 1, type: "spring" }}
      className="relative w-48 h-48 bg-emerald-500/20 rounded-full border-4 border-emerald-500 flex items-center justify-center shadow-[0_0_50px_#10b981]"
    >
      <ShieldCheck className="w-24 h-24 text-emerald-400" />
    </motion.div>
  );
}

// 12. Frameworks
function FoundationalFrameworksWidget() {
  return (
    <div className="flex gap-2">
      {['MITRE', 'D3FEND', 'NIST'].map((text, i) => (
        <motion.div
          key={i}
          animate={{ y: [0, -20, 0] }}
          transition={{ duration: 2, delay: i * 0.3, repeat: Infinity }}
          className="w-24 h-24 bg-slate-800 rounded-xl border border-cyan-500 flex items-center justify-center text-cyan-400 font-bold shadow-[0_0_15px_#06b6d4]"
        >
          {text}
        </motion.div>
      ))}
    </div>
  );
}

// 13. Compliance
function ComplianceStandardsWidget() {
  return (
    <div className="relative w-64 h-64 flex flex-col items-center justify-center gap-4 border-2 border-dashed border-indigo-500/50 rounded-full p-8">
      <Lock className="w-16 h-16 text-indigo-400" />
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
        className="absolute inset-0 border border-indigo-500/20 rounded-full"
      />
    </div>
  );
}

// 14. AI Stack
function AIMLStackWidget() {
  return (
    <div className="flex flex-col gap-2">
      {['SecureBERT', 'MPNet-Base-V2', 'Groq LPU', 'Llama 3 70B'].map((text, i) => (
        <motion.div
          key={i}
          initial={{ x: -50, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ delay: i * 0.2 }}
          className="w-64 h-12 bg-slate-800 border-l-4 border-emerald-500 flex items-center px-4 text-emerald-400 font-mono shadow-[0_0_10px_#10b981]"
        >
          {text}
        </motion.div>
      ))}
    </div>
  );
}

// 15. Tech Stack
function PrimaryTechStackWidget() {
  return (
    <div className="relative w-64 h-64 flex items-center justify-center">
      <Server className="w-16 h-16 text-cyan-500 absolute" />
      {[0, 1, 2].map((i) => (
        <motion.div
          key={i}
          animate={{ rotate: 360 }}
          transition={{ duration: 5 + i * 2, repeat: Infinity, ease: "linear" }}
          className="absolute w-full h-full rounded-full border border-cyan-500/30 border-dashed"
        >
          <div className="absolute top-0 left-1/2 w-4 h-4 bg-cyan-400 rounded-full shadow-[0_0_10px_#22d3ee] -translate-x-1/2 -translate-y-1/2" />
        </motion.div>
      ))}
    </div>
  );
}

// 16. Auto Mitigation
function AutoMitigationWidget() {
  return (
    <div className="flex items-center gap-4">
      <AlertTriangle className="w-16 h-16 text-red-500 animate-pulse" />
      <motion.div
        animate={{ width: ["0px", "100px"] }}
        transition={{ duration: 1, repeat: Infinity }}
        className="h-1 bg-cyan-500"
      />
      <ShieldCheck className="w-16 h-16 text-emerald-500" />
    </div>
  );
}

// 17. Predictive Forecast
function PredictiveForecastingWidget() {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-2">
        <div className="w-8 h-8 rounded bg-red-500" />
        <div className="w-8 h-8 rounded bg-red-500" />
      </div>
      <motion.div
        animate={{ opacity: [0, 1, 0] }}
        transition={{ duration: 1, repeat: Infinity }}
        className="w-8 h-8 rounded bg-orange-500 shadow-[0_0_20px_#f97316]"
      />
    </div>
  );
}

// 18. Dashboard Features
function InteractiveDashboardWidget() {
  return (
    <div className="w-64 h-48 bg-slate-800 rounded-xl border border-slate-700 p-2 flex flex-col gap-2 shadow-[0_0_20px_#0f172a]">
      <div className="w-full h-8 bg-slate-700 rounded flex items-center px-2">
        <div className="w-3 h-3 bg-red-500 rounded-full mr-1" />
        <div className="w-3 h-3 bg-yellow-500 rounded-full mr-1" />
        <div className="w-3 h-3 bg-green-500 rounded-full" />
      </div>
      <div className="flex gap-2 flex-1">
        <div className="w-1/3 bg-slate-700 rounded p-1 flex flex-col justify-end">
          <motion.div animate={{ height: ["20%", "80%", "40%"] }} transition={{ duration: 2, repeat: Infinity }} className="w-full bg-cyan-500 rounded-sm mb-1" />
          <motion.div animate={{ height: ["50%", "30%", "90%"] }} transition={{ duration: 2.5, repeat: Infinity }} className="w-full bg-emerald-500 rounded-sm" />
        </div>
        <div className="w-2/3 bg-slate-700 rounded" />
      </div>
    </div>
  );
}

// 19. Live Export
function LiveExportWidget() {
  return (
    <div className="relative flex items-center justify-center">
      <FileJson className="w-24 h-24 text-indigo-500" />
      <motion.div
        animate={{ y: [0, -50], opacity: [1, 0] }}
        transition={{ duration: 1, repeat: Infinity }}
        className="absolute text-indigo-400 font-mono font-bold"
      >
        {"{STIX}"}
      </motion.div>
    </div>
  );
}

// 20. Validation Results
function ValidationResultsWidget() {
  return (
    <div className="relative w-48 h-48 rounded-full border-8 border-slate-800 flex items-center justify-center">
      <motion.svg className="absolute inset-0 w-full h-full -rotate-90">
        <motion.circle
          cx="96" cy="96" r="88"
          fill="none"
          stroke="#10b981"
          strokeWidth="16"
          strokeLinecap="round"
          initial={{ strokeDasharray: "0 1000" }}
          animate={{ strokeDasharray: "550 1000" }}
          transition={{ duration: 2 }}
        />
      </motion.svg>
      <div className="text-4xl font-bold text-emerald-400 shadow-[0_0_20px_#10b981_inset]">96%</div>
    </div>
  );
}

// 21. Key Findings
function KeyFindingsWidget() {
  return (
    <div className="relative flex items-center justify-center">
      <Lightbulb className="w-32 h-32 text-yellow-500" />
      <motion.div
        animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0, 0.5] }}
        transition={{ duration: 2, repeat: Infinity }}
        className="absolute inset-0 bg-yellow-500 rounded-full blur-xl"
      />
    </div>
  );
}

// 22. Limitations
function AcknowledgedLimitationsWidget() {
  return (
    <div className="flex flex-col items-center gap-4">
      <Lock className="w-24 h-24 text-red-500" />
      <div className="px-4 py-2 bg-red-500/20 text-red-400 font-mono rounded border border-red-500">
        TLS 1.3 ENCRYPTED
      </div>
    </div>
  );
}

// 23. Real World Value
function RealWorldValueWidget() {
  return (
    <div className="flex items-center gap-8">
      <div className="text-red-500 font-mono text-3xl line-through opacity-50">4 HOURS</div>
      <motion.div
        animate={{ x: [0, 10, 0] }}
        transition={{ duration: 1, repeat: Infinity }}
      >
        <Rocket className="w-12 h-12 text-emerald-500" />
      </motion.div>
      <div className="text-emerald-400 font-mono text-5xl font-bold text-shadow-[0_0_20px_#10b981]">0.8s</div>
    </div>
  );
}

// 24. Conclusion
function ConclusionWidget() {
  return (
    <div className="relative w-64 h-64 bg-slate-900 rounded-full border-4 border-cyan-500 flex flex-col items-center justify-center shadow-[0_0_50px_#06b6d4]">
      <CheckCircle className="w-24 h-24 text-cyan-400 mb-2" />
      <div className="text-cyan-400 font-bold tracking-widest">SYSTEM READY</div>
    </div>
  );
}
