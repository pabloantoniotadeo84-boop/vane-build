import type { AttestationRecord } from '@/app/page';

const ACTION_COLORS: Record<string, string> = {
  'db.write': 'text-violet-400 bg-violet-950/50 border-violet-800/40',
  'db.query': 'text-blue-400 bg-blue-950/50 border-blue-800/40',
  'db.read': 'text-sky-400 bg-sky-950/50 border-sky-800/40',
  'http.post': 'text-amber-400 bg-amber-950/50 border-amber-800/40',
  'http.get': 'text-yellow-400 bg-yellow-950/50 border-yellow-800/40',
  'fs.read': 'text-teal-400 bg-teal-950/50 border-teal-800/40',
  'fs.write': 'text-cyan-400 bg-cyan-950/50 border-cyan-800/40',
};

const DEFAULT_ACTION_COLOR = 'text-slate-400 bg-slate-900/50 border-slate-700/40';

function actionColor(actionType?: string) {
  if (!actionType) return DEFAULT_ACTION_COLOR;
  const lower = actionType.toLowerCase();
  for (const key of Object.keys(ACTION_COLORS)) {
    if (lower.includes(key)) return ACTION_COLORS[key];
  }
  return DEFAULT_ACTION_COLOR;
}

function formatTimestamp(iso: string) {
  const d = new Date(iso);
  return {
    date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
    time: d.toLocaleTimeString('en-US', { hour12: false }),
  };
}

export default function RecordCard({ record }: { record: AttestationRecord }) {
  const { agentId, actionType } = record.payload ?? {};
  const { date, time } = formatTimestamp(record.timestamp);
  const hashShort = record.hash.slice(0, 8) + '…' + record.hash.slice(-6);
  const prevShort = record.previousHash.startsWith('0000000')
    ? 'genesis'
    : record.previousHash.slice(0, 8) + '…';
  const color = actionColor(actionType);

  return (
    <div className="group relative rounded-xl border border-[#21262d] bg-[#0d1117] hover:border-[#30363d] transition-colors duration-150 overflow-hidden">
      {/* Top accent line */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-violet-500/20 to-transparent" />

      <div className="px-4 pt-4 pb-3">
        {/* Header row */}
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center justify-center rounded-md bg-[#161b22] border border-[#21262d] px-2 py-0.5 font-mono text-xs font-semibold text-[#7d8590] min-w-[2.5rem]">
              #{record.index}
            </span>
            {actionType && (
              <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium font-mono ${color}`}>
                {actionType}
              </span>
            )}
          </div>
        </div>

        {/* Agent ID */}
        {agentId ? (
          <div className="mb-3">
            <p className="text-[10px] uppercase tracking-wider text-[#4d565e] mb-0.5">Agent</p>
            <p className="text-sm text-[#e6edf3] font-medium truncate" title={agentId}>
              {agentId}
            </p>
          </div>
        ) : (
          <div className="mb-3">
            <p className="text-[10px] uppercase tracking-wider text-[#4d565e] mb-0.5">Agent</p>
            <p className="text-sm text-[#4d565e] italic">unknown</p>
          </div>
        )}

        {/* Hash */}
        <div className="mb-3">
          <p className="text-[10px] uppercase tracking-wider text-[#4d565e] mb-0.5">Hash</p>
          <p className="font-mono text-xs text-[#58a6ff] bg-[#161b22] rounded px-2 py-1 truncate" title={record.hash}>
            {hashShort}
          </p>
        </div>

        {/* Footer */}
        <div className="pt-2.5 border-t border-[#21262d] flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" className="text-[#4d565e] shrink-0">
              <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.5" />
              <path d="M12 6v6l4 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <span className="text-[11px] text-[#4d565e]">{date}</span>
            <span className="text-[11px] text-[#4d565e] font-mono">{time}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" className="text-[#4d565e]">
              <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <span className="font-mono text-[10px] text-[#4d565e]" title={record.previousHash}>
              prev: {prevShort}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
