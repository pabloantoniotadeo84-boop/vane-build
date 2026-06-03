'use client';

import { useEffect, useRef, useState } from 'react';
import RecordCard from '@/components/RecordCard';
import ChainBadge from '@/components/ChainBadge';

export interface AttestationPayload {
  agentId?: string;
  companyId?: string;
  actionType?: string;
  payload?: unknown;
  [key: string]: unknown;
}

export interface AttestationRecord {
  index: number;
  timestamp: string;
  payload: AttestationPayload;
  previousHash: string;
  hash: string;
  signature: string;
}

interface ChainResponse {
  records: AttestationRecord[];
}

interface VerifyResponse {
  valid: boolean;
  failedAtIndex?: number;
}

type WsStatus = 'connecting' | 'connected' | 'disconnected';

const API_BASE = '/api';
const WS_URL = process.env.NEXT_PUBLIC_VANE_WS_URL ?? 'ws://localhost:3000/v1/ws';

export default function Dashboard() {
  const [records, setRecords] = useState<AttestationRecord[]>([]);
  const [verify, setVerify] = useState<VerifyResponse | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [wsStatus, setWsStatus] = useState<WsStatus>('connecting');
  const wsRef = useRef<WebSocket | null>(null);

  async function fetchChain() {
    try {
      const [chainRes, verifyRes] = await Promise.all([
        fetch(`${API_BASE}/v1/chain`),
        fetch(`${API_BASE}/v1/verify`),
      ]);

      if (!chainRes.ok || !verifyRes.ok) {
        throw new Error(`API error: chain=${chainRes.status} verify=${verifyRes.status}`);
      }

      const chainData: ChainResponse = await chainRes.json();
      const verifyData: VerifyResponse = await verifyRes.json();

      setRecords(chainData.records.slice().reverse());
      setVerify(verifyData);
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reach API');
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    fetchChain();

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setWsStatus('connected');

    ws.onmessage = (event: MessageEvent) => {
      try {
        const msg = JSON.parse(event.data as string) as {
          type: string;
          record: AttestationRecord;
          valid: boolean;
          failedAtIndex?: number;
          merkleRoot?: string;
        };
        if (msg.type === 'record') {
          setRecords((prev) => [msg.record, ...prev]);
          setVerify({ valid: msg.valid, failedAtIndex: msg.failedAtIndex });
          setLastUpdated(new Date());
          setError(null);
        }
      } catch {
        // malformed message — ignore
      }
    };

    ws.onerror = () => setWsStatus('disconnected');
    ws.onclose = () => setWsStatus('disconnected');

    return () => {
      ws.close();
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0c10]">
      {/* Header */}
      <header className="border-b border-[#21262d] bg-[#0d1117]">
        <div className="mx-auto max-w-7xl px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" className="text-violet-400">
                <path
                  d="M12 2L3 7v10l9 5 9-5V7L12 2z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                />
                <path d="M12 2v20M3 7l9 5 9-5" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
              </svg>
              <span className="text-[15px] font-semibold text-[#e6edf3] tracking-tight">vane</span>
            </div>
            <span className="text-[#4d565e] text-sm">/</span>
            <span className="text-sm text-[#7d8590]">attestation chain</span>
          </div>

          <div className="flex items-center gap-4">
            {lastUpdated && (
              <span className="text-xs text-[#4d565e] font-mono tabular-nums">
                updated {lastUpdated.toLocaleTimeString()}
              </span>
            )}
            <ChainBadge verify={verify} isLoading={isLoading} />
          </div>
        </div>
      </header>

      {/* Stats bar */}
      <div className="border-b border-[#21262d] bg-[#0d1117]">
        <div className="mx-auto max-w-7xl px-6 py-3 flex items-center gap-6">
          <Stat label="Total Records" value={records.length} />
          <div className="h-4 w-px bg-[#21262d]" />
          <Stat label="Latest Index" value={records.length > 0 ? records[0].index : '—'} />
          <div className="h-4 w-px bg-[#21262d]" />
          <Stat
            label="Unique Agents"
            value={new Set(records.map((r) => r.payload?.agentId).filter(Boolean)).size}
          />
          <div className="h-4 w-px bg-[#21262d]" />
          <div className="ml-auto flex items-center gap-2">
            <WsIndicator status={wsStatus} />
          </div>
        </div>
      </div>

      {/* Content */}
      <main className="mx-auto max-w-7xl px-6 py-8">
        {error && (
          <div className="mb-6 rounded-lg border border-red-900/50 bg-red-950/30 px-4 py-3 flex items-center gap-3">
            <svg className="text-red-400 shrink-0" width="16" height="16" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.5" />
              <path d="M12 8v4M12 16h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
            <span className="text-sm text-red-300">{error}</span>
            <span className="text-xs text-red-500 ml-auto">
              Ensure the Vane API is running on <span className="font-mono">localhost:3000</span>
            </span>
          </div>
        )}

        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-32 gap-4">
            <div className="h-8 w-8 rounded-full border-2 border-violet-500/30 border-t-violet-500 animate-spin" />
            <span className="text-sm text-[#4d565e]">Connecting to attestation chain…</span>
          </div>
        ) : records.length === 0 && !error ? (
          <div className="flex flex-col items-center justify-center py-32 gap-3">
            <div className="rounded-full border border-[#21262d] p-4 mb-2">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-[#4d565e]">
                <path
                  d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                />
              </svg>
            </div>
            <p className="text-[#7d8590] text-sm">No attestation records yet</p>
            <p className="text-[#4d565e] text-xs">
              POST to <span className="font-mono">/v1/attest</span> to create the first record
            </p>
          </div>
        ) : (
          <>
            <div className="mb-5 flex items-center justify-between">
              <h2 className="text-sm font-medium text-[#7d8590] uppercase tracking-wider">
                Attestation Records
              </h2>
              <span className="text-xs text-[#4d565e]">newest first</span>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {records.map((record) => (
                <RecordCard key={record.index} record={record} />
              ))}
            </div>
          </>
        )}
      </main>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-[#4d565e]">{label}</span>
      <span className="text-sm font-semibold text-[#e6edf3] tabular-nums font-mono">{value}</span>
    </div>
  );
}

function WsIndicator({ status }: { status: WsStatus }) {
  if (status === 'connected') {
    return (
      <>
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
        </span>
        <span className="text-xs text-[#7d8590]">live · websocket</span>
      </>
    );
  }
  if (status === 'connecting') {
    return (
      <>
        <span className="relative flex h-2 w-2">
          <span className="relative inline-flex rounded-full h-2 w-2 bg-[#4d565e] animate-pulse" />
        </span>
        <span className="text-xs text-[#7d8590]">connecting…</span>
      </>
    );
  }
  return (
    <>
      <span className="relative flex h-2 w-2">
        <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500" />
      </span>
      <span className="text-xs text-[#7d8590]">disconnected · data may be stale</span>
    </>
  );
}
