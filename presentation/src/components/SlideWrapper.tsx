import { motion } from 'framer-motion';
import type { SlideData } from '../data/slides';
import { Shield } from 'lucide-react';

// Existing widgets
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

// New widgets
import ThreatSurge from './widgets/ThreatSurge';
import FragmentationMap from './widgets/FragmentationMap';
import AlertFatigueMeter from './widgets/AlertFatigueMeter';
import ManualMappingHell from './widgets/ManualMappingHell';
import GapVenn from './widgets/GapVenn';
import ComparisonRadar from './widgets/ComparisonRadar';
import ComparisonTable from './widgets/ComparisonTable';
import LitReviewLayer from './widgets/LitReviewLayer';
import ContributionBridge from './widgets/ContributionBridge';
import ObjectivesGrid from './widgets/ObjectivesGrid';
import StakeholderOrbit from './widgets/StakeholderOrbit';
import FRPipeline from './widgets/FRPipeline';
import NFRRadar from './widgets/NFRRadar';
import DesignDecisionTree from './widgets/DesignDecisionTree';
import ArchOverview from './widgets/ArchOverview';
import NLPPipeline from './widgets/NLPPipeline';
import PCAPFlow from './widgets/PCAPFlow';
import SecureBERTBrain from './widgets/SecureBERTBrain';
import RAGMechanism from './widgets/RAGMechanism';
import LLMFailover from './widgets/LLMFailover';
import FrameworkMapper from './widgets/FrameworkMapper';
import MitigationFlow from './widgets/MitigationFlow';
import APIRoutes from './widgets/APIRoutes';
import TechStackWheel from './widgets/TechStackWheel';
import TestMatrix from './widgets/TestMatrix';
import MappingAccuracy from './widgets/MappingAccuracy';
import AccuracyContext from './widgets/AccuracyContext';
import CaseStudyWalkthrough from './widgets/CaseStudyWalkthrough';
import FailoverTest from './widgets/FailoverTest';
import LoadTest from './widgets/LoadTest';
import FRValidation from './widgets/FRValidation';
import LimitationsGauge from './widgets/LimitationsGauge';
import FutureRoadmap from './widgets/FutureRoadmap';
import ConclusionShield from './widgets/ConclusionShield';
import DataFlowDiagram from './widgets/DataFlowDiagram';
import SemanticReranker from './widgets/SemanticReranker';
import ThreatSeverity from './widgets/ThreatSeverity';
import PredictionEngine from './widgets/PredictionEngine';
import SiemSoarIntegration from './widgets/SiemSoarIntegration';

export default function SlideWrapper({ slide }: { slide: SlideData }) {
  const isTitle = slide.layout === 'title';
  const isSplit = slide.layout === 'split';

  const renderWidget = () => {
    if (!slide.widget) return <DynamicCyberArt seed={slide.id} />;
    switch (slide.widget) {
      // Existing
      case 'latency':           return <LatencyChart />;
      case 'accuracy':          return <AccuracyMetrics />;
      case 'architecture':      return <InteractiveArchitecture />;
      case 'simulator':         return <ThreatMappingSimulator />;
      case 'guardrail':         return <HallucinationGuardrail />;
      case 'hardware':          return <HardwareMonitor />;
      case 'dbscan':            return <DBSCANClustering />;
      case 'intake':            return <DataIntakeHub />;
      case 'siem_funnel':       return <SIEMFunnel />;
      case 'stix_tree':         return <STIXTree />;
      // New
      case 'threat_surge':           return <ThreatSurge />;
      case 'fragmentation_map':      return <FragmentationMap />;
      case 'alert_fatigue_meter':    return <AlertFatigueMeter />;
      case 'manual_mapping_hell':    return <ManualMappingHell />;
      case 'gap_venn':               return <GapVenn />;
      case 'comparison_radar':       return <ComparisonRadar />;
      case 'comparison_table':       return <ComparisonTable />;
      case 'lit_review_layer':       return <LitReviewLayer />;
      case 'contribution_bridge':    return <ContributionBridge />;
      case 'objectives_grid':        return <ObjectivesGrid />;
      case 'stakeholder_orbit':      return <StakeholderOrbit />;
      case 'fr_pipeline':            return <FRPipeline />;
      case 'nfr_radar':              return <NFRRadar />;
      case 'design_decision_tree':   return <DesignDecisionTree />;
      case 'arch_overview':          return <ArchOverview />;
      case 'nlp_pipeline':           return <NLPPipeline />;
      case 'pcap_flow':              return <PCAPFlow />;
      case 'securebert_brain':       return <SecureBERTBrain />;
      case 'rag_mechanism':          return <RAGMechanism />;
      case 'llm_failover':           return <LLMFailover />;
      case 'framework_mapper':       return <FrameworkMapper />;
      case 'mitigation_flow':        return <MitigationFlow />;
      case 'api_routes':             return <APIRoutes />;
      case 'tech_stack_wheel':       return <TechStackWheel />;
      case 'test_matrix':            return <TestMatrix />;
      case 'mapping_accuracy':       return <MappingAccuracy />;
      case 'accuracy_context':       return <AccuracyContext />;
      case 'case_study_walkthrough': return <CaseStudyWalkthrough />;
      case 'failover_test':          return <FailoverTest />;
      case 'load_test':              return <LoadTest />;
      case 'fr_validation':          return <FRValidation />;
      case 'limitations_gauge':      return <LimitationsGauge />;
      case 'data_flow_diagram':      return <DataFlowDiagram />;
      case 'semantic_reranker':      return <SemanticReranker />;
      case 'threat_severity':        return <ThreatSeverity />;
      case 'prediction_engine':      return <PredictionEngine />;
      case 'future_roadmap':         return <FutureRoadmap />;
      case 'siem_soar_integration':  return <SiemSoarIntegration />;
      case 'conclusion_shield':      return <ConclusionShield />;
      case 'none':                   return null;
      default:                       return <DynamicCyberArt seed={slide.id} />;
    }
  };

  // ── Title Slide ──────────────────────────────────────────────
  if (isTitle) {
    const widget = renderWidget();
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.8, filter: 'blur(20px)' }}
        animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
        exit={{ opacity: 0, scale: 1.1, filter: 'blur(20px)' }}
        transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-5xl h-full flex flex-col items-center justify-center text-center relative"
      >
        {/* Background shield logo — only on slides without a widget */}
        {!slide.widget && (
          <motion.div
            animate={{ scale: [1, 1.05, 1], opacity: [0.3, 0.6, 0.3] }}
            transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
            className="absolute z-0 flex items-center justify-center"
          >
            <Shield className="w-96 h-96 text-cyan-900/40" strokeWidth={0.5} />
          </motion.div>
        )}

        <div className="z-10 flex flex-col items-center justify-center w-full gap-6">
          <motion.h1
            initial={{ y: 30, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="text-7xl font-bold tracking-tighter text-slate-50 glitch-text-container"
            data-text={slide.title}
          >
            {slide.title}
          </motion.h1>

          <ul className="space-y-4 w-full max-w-3xl">
            {slide.content.map((point, idx) => (
              <motion.li
                key={idx}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.5 + idx * 0.2 }}
                className="text-2xl text-slate-300 font-light leading-relaxed"
              >
                {point}
              </motion.li>
            ))}
          </ul>

          {/* Widget (e.g. ConclusionShield on final slide) */}
          {widget && (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.8 }}
              className="w-full max-w-2xl h-72 glass-card flex items-center justify-center overflow-hidden"
            >
              {widget}
            </motion.div>
          )}
        </div>
      </motion.div>
    );
  }

  // ── Content / Split Slide ────────────────────────────────────
  return (
    <motion.div
      initial={{ opacity: 0, x: 50, filter: 'blur(10px)' }}
      animate={{ opacity: 1, x: 0, filter: 'blur(0px)' }}
      exit={{ opacity: 0, x: -50, filter: 'blur(10px)' }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      className="w-full max-w-7xl h-[80vh] flex flex-col justify-start"
    >
      {/* Slide header */}
      <div className="mb-8 w-full relative">
        <motion.span
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="text-emerald-400 font-mono text-lg uppercase tracking-widest mb-4 block"
        >
          {slide.section}
        </motion.span>

        <motion.h1
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="font-bold tracking-tight text-5xl text-slate-50 pb-5 relative"
        >
          {slide.title}
          <div className="absolute bottom-0 left-0 h-[1px] bg-gradient-to-r from-cyan-500 via-emerald-400 to-transparent w-full" />
        </motion.h1>
      </div>

      {/* Body */}
      <div className={`flex-grow flex ${isSplit ? 'flex-row gap-12 items-center' : 'flex-col items-center justify-center'} w-full`}>
        {/* Bullet points */}
        <div className={`${isSplit ? 'w-5/12' : 'w-full max-w-4xl'} flex flex-col justify-center h-full`}>
          <ul className="space-y-3 w-full">
            {slide.content.map((point, idx) => (
              <motion.li
                key={idx}
                initial={{ opacity: 0, x: -30, rotateX: 20 }}
                animate={{ opacity: 1, x: 0, rotateX: 0 }}
                whileHover={{ scale: 1.02, x: 10, borderColor: 'rgba(34,211,238,0.5)', backgroundColor: 'rgba(15,23,42,0.8)' }}
                transition={{ duration: 0.4, delay: 0.4 + idx * 0.15 }}
                className="text-xl flex items-center bg-slate-900/40 px-5 py-4 rounded-xl border border-slate-800/50 cursor-default transition-colors duration-300 shadow-lg hover:shadow-[0_0_15px_rgba(34,211,238,0.2)] backdrop-blur-sm"
              >
                <span className="text-cyan-500 mr-4 opacity-80 shrink-0 drop-shadow-[0_0_5px_rgba(34,211,238,0.8)]">▸</span>
                <span className="leading-relaxed text-slate-200">{point}</span>
              </motion.li>
            ))}
          </ul>
        </div>

        {/* Widget panel */}
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
