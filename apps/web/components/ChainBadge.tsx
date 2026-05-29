interface VerifyResponse {
  valid: boolean;
  failedAtIndex?: number;
}

interface Props {
  verify: VerifyResponse | null;
  isLoading: boolean;
}

export default function ChainBadge({ verify, isLoading }: Props) {
  if (isLoading) {
    return (
      <div className="flex items-center gap-2 rounded-full border border-[#21262d] bg-[#161b22] px-3 py-1.5">
        <div className="h-1.5 w-1.5 rounded-full bg-[#4d565e] animate-pulse" />
        <span className="text-xs text-[#7d8590]">checking chain…</span>
      </div>
    );
  }

  if (!verify) {
    return (
      <div className="flex items-center gap-2 rounded-full border border-[#21262d] bg-[#161b22] px-3 py-1.5">
        <div className="h-1.5 w-1.5 rounded-full bg-[#4d565e]" />
        <span className="text-xs text-[#7d8590]">unknown</span>
      </div>
    );
  }

  if (verify.valid) {
    return (
      <div className="flex items-center gap-2 rounded-full border border-emerald-800/60 bg-emerald-950/40 px-3 py-1.5">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" className="text-emerald-400">
          <path
            d="M20 6L9 17l-5-5"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
        <span className="text-xs font-medium text-emerald-400">chain verified</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 rounded-full border border-red-800/60 bg-red-950/40 px-3 py-1.5">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" className="text-red-400">
        <path
          d="M18 6L6 18M6 6l12 12"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
        />
      </svg>
      <span className="text-xs font-medium text-red-400">
        integrity failed
        {verify.failedAtIndex !== undefined && (
          <span className="text-red-500"> @ index {verify.failedAtIndex}</span>
        )}
      </span>
    </div>
  );
}
