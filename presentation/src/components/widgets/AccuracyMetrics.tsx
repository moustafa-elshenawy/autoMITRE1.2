import { RadialBarChart, RadialBar, Legend, Tooltip, ResponsiveContainer, PolarAngleAxis } from 'recharts';

const data = [
  { name: 'Precision', value: 25.0, fill: '#a855f7' },
  { name: 'F1-Score', value: 32.4, fill: '#22d3ee' },
  { name: 'Recall', value: 46.0, fill: '#f59e0b' },
  { name: 'Severity Scoring', value: 60.0, fill: '#3b82f6' }
];

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="bg-slate-900/95 backdrop-blur-md border border-slate-700 p-4 rounded-xl shadow-2xl">
        <p className="text-sm font-bold tracking-wide uppercase mb-1" style={{ color: data.fill }}>
          {data.name}
        </p>
        <p className="text-3xl font-mono font-bold text-slate-50">
          {data.value}%
        </p>
      </div>
    );
  }
  return null;
};

export default function AccuracyMetrics() {
  return (
    <div className="w-full h-full p-8 flex flex-col">
      <h3 className="text-xl font-mono text-center mb-4 text-slate-300 border-b border-slate-700 pb-4">SecureBERT Accuracy Metrics (%)</h3>
      <div className="flex-grow flex items-center justify-center">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart 
            cx="35%" 
            cy="50%" 
            innerRadius="40%" 
            outerRadius="85%" 
            barSize={32} 
            data={data}
            startAngle={180}
            endAngle={-180}
          >
            <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
            <RadialBar
              background={{ fill: '#1e293b' }}
              dataKey="value"
              cornerRadius={10}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(30, 41, 59, 0.4)' }} />
            <Legend 
              iconSize={16} 
              layout="vertical" 
              verticalAlign="middle" 
              align="right"
              wrapperStyle={{ right: '5%', top: '50%', transform: 'translate(0, -50%)', color: '#f8fafc', fontSize: '16px' }} 
            />
          </RadialBarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
