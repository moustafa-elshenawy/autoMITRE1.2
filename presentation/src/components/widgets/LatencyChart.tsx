import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const data = [
  { name: 'Groq API (LPU)', time: 0.8, fill: '#22d3ee' },
  { name: 'Local Metal (MPS)', time: 5.2, fill: '#34d399' }
];

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="bg-slate-900/95 backdrop-blur-md border border-slate-700 p-4 rounded-xl shadow-[0_0_30px_rgba(34,211,238,0.2)]">
        <p className="text-sm font-bold tracking-wide uppercase mb-1" style={{ color: data.fill }}>
          {data.name}
        </p>
        <p className="text-3xl font-mono font-bold text-slate-50">
          {data.time}<span className="text-xl text-slate-400 ml-1">sec</span>
        </p>
      </div>
    );
  }
  return null;
};

export default function LatencyChart() {
  return (
    <div className="w-full h-full p-8 flex flex-col">
      <h3 className="text-xl font-mono text-center mb-8 text-slate-300 border-b border-slate-700 pb-4">Inference Latency (Seconds)</h3>
      <div className="flex-grow">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 20, right: 30, left: 40, bottom: 20 }}>
            <XAxis type="number" stroke="#475569" tick={{ fill: '#94a3b8' }} domain={[0, 7]} />
            <YAxis dataKey="name" type="category" stroke="#475569" tick={{ fill: '#f8fafc', fontSize: 14 }} width={140} />
            <Tooltip 
              cursor={{ fill: 'rgba(30, 41, 59, 0.4)' }}
              content={<CustomTooltip />}
            />
            <Bar 
              dataKey="time" 
              radius={[0, 8, 8, 0]} 
              barSize={60}
              activeBar={{ stroke: '#fff', strokeWidth: 2, filter: 'drop-shadow(0 0 15px rgba(255,255,255,0.6))' }}
              animationDuration={1500}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} style={{ filter: `drop-shadow(0 0 8px ${entry.fill}80)` }} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
