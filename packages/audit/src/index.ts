#!/usr/bin/env node
import { runAudit } from './checks.js';
import { printReport } from './report.js';

const USAGE = `
  vane-audit — audit an MCP server for cryptographic agent accountability

  Usage:
    npx @vane.build/audit <mcp-server-url>

  Example:
    npx @vane.build/audit https://my-agent.company.com

  Runs four checks against your MCP server and prints what an auditor will ask
  that your server cannot currently answer. No signup. No data leaves your
  machine. Exits 0 if all checks pass, 1 otherwise.
`;

// Accept a bare host and default it to https:// so "company.com" works.
function normalizeUrl(input: string): string | null {
  let candidate = input.trim();
  if (candidate.length === 0) return null;
  if (!/^https?:\/\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }
  try {
    return new URL(candidate).toString().replace(/\/$/, '');
  } catch {
    return null;
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const first = args[0];

  if (!first || first === '-h' || first === '--help') {
    process.stdout.write(`${USAGE}\n`);
    process.exit(first ? 0 : 1);
  }

  const url = normalizeUrl(first);
  if (!url) {
    process.stderr.write(`\n  Invalid URL: "${first}"\n${USAGE}\n`);
    process.exit(1);
  }

  const report = await runAudit(url);
  printReport(report);

  // Non-zero exit when any check failed so the tool is CI-usable.
  process.exit(report.passedCount === report.totalCount ? 0 : 1);
}

main().catch((err) => {
  // runAudit is designed never to throw; this is a last-resort guard so the CLI
  // exits cleanly rather than printing an unhandled-rejection stack trace.
  process.stderr.write(`\n  vane-audit encountered an unexpected error: ${(err as Error).message}\n`);
  process.exit(1);
});
