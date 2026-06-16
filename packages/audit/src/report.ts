import type { AuditReport, CheckResult } from './types.js';

// ── ANSI (no dependencies — these are the only escape codes used) ────────────

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const RESET = '\x1b[0m';

// Honor NO_COLOR (https://no-color.org) and non-TTY pipes by stripping codes.
const COLOR_ENABLED = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;

function paint(code: string, text: string): string {
  return COLOR_ENABLED ? `${code}${text}${RESET}` : text;
}

const red = (t: string) => paint(RED, t);
const green = (t: string) => paint(GREEN, t);

// Divider lines are exactly 36 dashes.
const DIVIDER = '-'.repeat(36);
// Two spaces of indent on every line inside the report.
const PAD = '  ';

function line(s = ''): void {
  process.stdout.write(`${PAD}${s}\n`);
}

// Split a detail string into its individual sentences so each prints on its own
// paragraph, matching the report format. Splits on sentence-ending punctuation
// followed by a capital letter; single-sentence details return one element.
function toSentences(detail: string): string[] {
  return detail
    .split(/(?<=[.?])\s+(?=[A-Z])/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// ── Single check block ────────────────────────────────────────────────────────
//
// Layout (no trailing blank — the next check's mark, or the divider, hugs it):
//   <mark>  <label>
//   <blank>
//   <sentence 1>
//   <blank>
//   <sentence 2>

function printCheck(result: CheckResult): void {
  const mark = result.passed ? green('✓') : red('✗');
  line(`${mark}  ${result.label}`);
  const sentences = toSentences(result.detail);
  sentences.forEach((sentence) => {
    line();
    line(sentence);
  });
}

// ── Report ────────────────────────────────────────────────────────────────────

/** Render a full AuditReport to stdout in the exact Vane format. */
export function printReport(report: AuditReport): void {
  const { results, passedCount, totalCount } = report;
  const failed = results.filter((r) => !r.passed);

  line();
  line('▸ VANE AUDIT');
  line();
  line(`Scanning ${report.url}...`);
  line('AGENT ACCOUNTABILITY REPORT');
  line();
  line(DIVIDER);

  for (const result of results) {
    printCheck(result);
  }

  line(DIVIDER);
  line();
  line(`${passedCount} of ${totalCount} checks passed.`);

  if (passedCount === totalCount) {
    line(green('✓ All checks passed. Your agents are accountable.'));
  } else {
    line('AN AUDITOR WILL ASK:');
    failed.forEach((f, i) => {
      if (i > 0) line();
      line(`→ ${f.auditQuestion}`);
    });
    line('You cannot answer any of these questions right now.');
  }

  line(DIVIDER);
  line();
  line('Fix this:      https://vane.build/docs');
  line();
  line('Talk to us:    https://vane.build/enterprise');
  line();
  line(DIVIDER);
  line();
}
