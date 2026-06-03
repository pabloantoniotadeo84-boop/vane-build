/**
 * @vane.build/openai-agents
 *
 * Attests every tool call made by an OpenAI Agents SDK agent to Vane.
 *
 * @example
 * import { createVaneHooks } from '@vane.build/openai-agents';
 * const hooks = createVaneHooks({ baseUrl, apiKey, agentId });
 * await run(agent, 'Review this contract.', { hooks });
 */

export interface VaneAgentOptions {
  /** Vane API base URL */
  baseUrl: string;
  /** Vane API key (Bearer token) */
  apiKey: string;
  /** Agent ID that will appear on every attestation record */
  agentId: string;
  /** Optional company ID; if omitted the API key's company is used */
  companyId?: string;
}

// Structural match for @openai/agents RunHooks — no import needed.
// If @openai/agents changes the hook signatures, users will get a type
// error at the call site (run(agent, input, { hooks })), not here.
export interface VaneRunHooks {
  onToolStart?: (
    context: object,
    agent: { name?: string },
    tool: { name?: string },
  ) => Promise<void>;
  onToolEnd?: (
    context: object,
    agent: { name?: string },
    tool: { name?: string },
    result: string,
  ) => Promise<void>;
  onAgentStart?: (
    context: object,
    agent: { name?: string },
  ) => Promise<void>;
  onAgentEnd?: (
    context: object,
    agent: { name?: string },
    output: unknown,
  ) => Promise<void>;
  onHandoff?: (
    context: object,
    agent: { name?: string },
    targetAgent: { name?: string },
  ) => Promise<void>;
}

interface PendingTool {
  agentName: string;
  toolName: string;
  startedAt: number;
}

/**
 * Returns a RunHooks object for the OpenAI Agents SDK that sends a signed
 * attestation record to Vane for every tool invocation.
 *
 * Pass the result directly as the `hooks` option to `run()`:
 *
 *   const hooks = createVaneHooks({ baseUrl, apiKey, agentId });
 *   await run(agent, input, { hooks });
 */
export function createVaneHooks(options: VaneAgentOptions): VaneRunHooks {
  const base = options.baseUrl.replace(/\/$/, '');
  const companyId = options.companyId ?? '';

  // Keyed by "${agentName}::${toolName}" — sufficient because a given agent
  // does not call the same tool twice concurrently within a single turn.
  const pending = new Map<string, PendingTool>();

  function attest(actionType: string, payload: unknown): void {
    fetch(`${base}/v1/attest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${options.apiKey}`,
      },
      body: JSON.stringify({
        agentId: options.agentId,
        companyId,
        actionType,
        payload,
      }),
    }).catch((err: unknown) => {
      console.error('[Vane] attest failed:', err);
    });
  }

  return {
    async onToolStart(_context, agent, tool) {
      const key = pendingKey(agent.name, tool.name);
      pending.set(key, {
        agentName: agent.name ?? 'unknown',
        toolName: tool.name ?? 'unknown',
        startedAt: Date.now(),
      });
    },

    async onToolEnd(_context, agent, tool, result) {
      const key = pendingKey(agent.name, tool.name);
      const p = pending.get(key);
      pending.delete(key);

      attest('tool-call', {
        agent: agent.name ?? 'unknown',
        tool: tool.name ?? 'unknown',
        output: result,
        durationMs: p !== undefined ? Date.now() - p.startedAt : undefined,
      });
    },

    async onAgentStart(_context, agent) {
      attest('agent-start', { agent: agent.name ?? 'unknown' });
    },

    async onAgentEnd(_context, agent, output) {
      attest('agent-end', {
        agent: agent.name ?? 'unknown',
        output: typeof output === 'string' ? output : JSON.stringify(output),
      });
    },

    async onHandoff(_context, agent, targetAgent) {
      attest('agent-handoff', {
        from: agent.name ?? 'unknown',
        to: targetAgent.name ?? 'unknown',
      });
    },
  };
}

function pendingKey(agentName: string | undefined, toolName: string | undefined): string {
  return `${agentName ?? ''}::${toolName ?? ''}`;
}
