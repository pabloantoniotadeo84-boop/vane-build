import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { parse } from 'yaml';

// These tests guard the CI gate itself: the workflow must be parseable, it must
// fire on the right events, and the supply-chain audit it runs must currently
// pass. If someone breaks the workflow YAML or introduces a high/critical
// advisory, the suite fails here rather than silently in GitHub Actions.

const repoRoot = process.cwd();

function readWorkflow(relPath: string): { raw: string; parsed: any } {
  const raw = readFileSync(resolve(repoRoot, relPath), 'utf8');
  // `yaml` parses against the YAML 1.2 core schema, so the `on:` key stays the
  // string "on" rather than being coerced to a boolean (as YAML 1.1 would).
  const parsed = parse(raw);
  return { raw, parsed };
}

describe('CI workflow (.github/workflows/ci.yml)', () => {
  it('is valid YAML and parses to an object', () => {
    const { parsed } = readWorkflow('.github/workflows/ci.yml');
    expect(parsed).toBeTypeOf('object');
    expect(parsed).not.toBeNull();
  });

  it('triggers on push to main', () => {
    const { parsed } = readWorkflow('.github/workflows/ci.yml');
    expect(parsed.on.push.branches).toContain('main');
  });

  it('triggers on pull_request to main', () => {
    const { parsed } = readWorkflow('.github/workflows/ci.yml');
    expect(parsed.on.pull_request.branches).toContain('main');
  });

  it('runs the test suite, a type check, and a high/critical audit gate', () => {
    const { raw } = readWorkflow('.github/workflows/ci.yml');
    expect(raw).toContain('npm test');
    expect(raw).toContain('tsc --noEmit');
    expect(raw).toContain('npm audit --audit-level=high');
  });
});

describe('Dependency review workflow (.github/workflows/dependency-review.yml)', () => {
  it('is valid YAML, runs only on pull requests, and blocks high severity', () => {
    const { raw, parsed } = readWorkflow('.github/workflows/dependency-review.yml');
    expect(parsed.on.pull_request).toBeDefined();
    expect(parsed.on.push).toBeUndefined();
    expect(raw).toContain('dependency-review-action');
    expect(raw).toContain('fail-on-severity: high');
  });
});

describe('Supply-chain posture', () => {
  it('npm audit --audit-level=high exits 0 on the current codebase', () => {
    // Throws (non-zero exit) if any high or critical advisory is present.
    expect(() =>
      execFileSync('npm', ['audit', '--audit-level=high'], {
        cwd: repoRoot,
        stdio: 'pipe',
      }),
    ).not.toThrow();
  });

  it('.npmrc disables install lifecycle scripts', () => {
    const npmrc = readFileSync(resolve(repoRoot, '.npmrc'), 'utf8');
    expect(npmrc).toMatch(/^ignore-scripts\s*=\s*true\s*$/m);
  });
});
