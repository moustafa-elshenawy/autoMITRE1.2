import { motion } from 'framer-motion';

const routes = [
  { method: 'POST', path: '/api/analyze/text', handler: 'text_pipeline.py',  color: '#0ea5e9', resp: '< 1.2s' },
  { method: 'POST', path: '/api/analyze/pcap', handler: 'pcap_parser.py',    color: '#8b5cf6', resp: '< 5s'   },
  { method: 'POST', path: '/api/analyze/file', handler: 'file_router.py',    color: '#10b981', resp: '< 2s'   },
  { method: 'GET',  path: '/api/threats',      handler: 'crud.py',            color: '#f59e0b', resp: '< 10ms' },
  { method: 'POST', path: '/api/export/stix',  handler: 'siem_exporter.py',  color: '#ec4899', resp: '< 0.5s' },
  { method: 'GET',  path: '/api/stats/trends', handler: 'stats_router.py',   color: '#06b6d4', resp: '< 50ms' },
];

const methodColors: Record<string, string> = { POST: '#f59e0b', GET: '#10b981' };

export default function APIRoutes() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-2.5">
      <p className="text-[11px] font-mono text-slate-400 uppercase tracking-widest">
        FastAPI Async REST Architecture
      </p>

      <div className="w-full flex flex-col gap-2">
        {routes.map((route, i) => (
          <motion.div
            key={route.path}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.12, duration: 0.4 }}
            className="flex items-center gap-3 bg-slate-900/50 border border-slate-800/50 rounded-lg px-3 py-2"
          >
            <span
              className="text-[10px] font-bold font-mono px-2 py-0.5 rounded shrink-0 min-w-[42px] text-center"
              style={{ color: methodColors[route.method], backgroundColor: `${methodColors[route.method]}20` }}
            >
              {route.method}
            </span>
            <span className="text-[11px] font-mono text-slate-200 flex-1">{route.path}</span>
            <span className="text-[9px] font-mono text-slate-500 hidden sm:block shrink-0">→ {route.handler}</span>
            <motion.span
              animate={{ color: route.color, opacity: [1, 0.5, 1] }}
              transition={{ duration: 2, repeat: Infinity, delay: i * 0.3 }}
              className="text-[10px] font-mono font-bold shrink-0 min-w-[48px] text-right"
            >
              {route.resp}
            </motion.span>
          </motion.div>
        ))}
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.2 }}
        className="text-[9px] text-slate-500 font-mono text-center mt-1"
      >
        Python 3.13 • Uvicorn ASGI • Async/Await throughout • SQLAlchemy ORM
      </motion.p>
    </div>
  );
}
