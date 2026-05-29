import { BaseCallbackHandler } from '@langchain/core/callbacks/base';
import type { Serialized } from '@langchain/core/load/serializable';
import type { LLMResult } from '@langchain/core/outputs';
import type { AgentAction } from '@langchain/core/agents';
import type { BaseMessage } from '@langchain/core/messages';

export interface CounselCallbackHandlerOptions {
  /** Counsel API base URL, e.g. https://your-counsel-instance.example.com */
  baseUrl: string;
  /** Counsel API key (Bearer token) */
  apiKey: string;
  /** Agent ID that will appear on every attestation record */
  agentId: string;
  /** Optional company ID; if omitted the API key's company is used */
  companyId?: string;
}

interface PendingLLM {
  modelName: string;
  prompts?: string[];
  messages?: string[][];
  startedAt: number;
}

interface PendingTool {
  toolName: string;
  input: string;
  startedAt: number;
}

/**
 * Attach to any LangChain LLM, chain, or agent executor to get a signed,
 * tamper-evident record in Counsel for every LLM call and tool invocation.
 *
 * @example
 * const handler = new CounselCallbackHandler({ baseUrl, apiKey, agentId });
 * const llm = new ChatOpenAI({ callbacks: [handler] });
 * await llm.invoke("Summarise this contract.");
 */
export class CounselCallbackHandler extends BaseCallbackHandler {
  readonly name = 'CounselCallbackHandler';

  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly agentId: string;
  private readonly companyId: string;

  // Keyed by LangChain runId — one entry per in-flight call.
  private readonly pendingLLMs = new Map<string, PendingLLM>();
  private readonly pendingTools = new Map<string, PendingTool>();

  constructor(options: CounselCallbackHandlerOptions) {
    super();
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.apiKey = options.apiKey;
    this.agentId = options.agentId;
    this.companyId = options.companyId ?? '';
  }

  // Fire-and-forget: attestation failures must never interrupt agent execution.
  private attest(actionType: string, payload: unknown): void {
    fetch(`${this.baseUrl}/v1/attest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        agentId: this.agentId,
        companyId: this.companyId,
        actionType,
        payload,
      }),
    }).catch((err: unknown) => {
      console.error('[Counsel] attest failed:', err);
    });
  }

  // ── LLM calls ──────────────────────────────────────────────────────────────

  override async handleLLMStart(
    llm: Serialized,
    prompts: string[],
    runId: string,
  ): Promise<void> {
    this.pendingLLMs.set(runId, {
      modelName: modelName(llm),
      prompts,
      startedAt: Date.now(),
    });
  }

  // Chat models go through handleChatModelStart, not handleLLMStart.
  override async handleChatModelStart(
    llm: Serialized,
    messages: BaseMessage[][],
    runId: string,
  ): Promise<void> {
    this.pendingLLMs.set(runId, {
      modelName: modelName(llm),
      messages: messages.map((turn) =>
        turn.map((m) => `[${m.getType()}] ${String(m.content)}`),
      ),
      startedAt: Date.now(),
    });
  }

  override async handleLLMEnd(output: LLMResult, runId: string): Promise<void> {
    const pending = this.pendingLLMs.get(runId);
    this.pendingLLMs.delete(runId);

    const text = output.generations?.[0]?.[0]?.text ?? '';
    this.attest('llm-call', {
      model: pending?.modelName ?? 'unknown',
      input: pending?.prompts ?? pending?.messages,
      output: text,
      tokenUsage: (output.llmOutput as Record<string, unknown> | undefined)?.tokenUsage,
      durationMs: pending !== undefined ? Date.now() - pending.startedAt : undefined,
    });
  }

  // ── Tool calls ─────────────────────────────────────────────────────────────

  override async handleToolStart(
    tool: Serialized,
    input: string,
    runId: string,
  ): Promise<void> {
    this.pendingTools.set(runId, {
      toolName: toolName(tool),
      input,
      startedAt: Date.now(),
    });
  }

  override async handleToolEnd(
    output: unknown,
    runId: string,
  ): Promise<void> {
    const pending = this.pendingTools.get(runId);
    this.pendingTools.delete(runId);

    // output is ToolMessage | string depending on LangChain version.
    const outputStr =
      typeof output === 'string'
        ? output
        : (output as { content?: unknown } | null)?.content !== undefined
          ? String((output as { content: unknown }).content)
          : JSON.stringify(output);

    this.attest('tool-call', {
      tool: pending?.toolName ?? 'unknown',
      input: pending?.input,
      output: outputStr,
      durationMs: pending !== undefined ? Date.now() - pending.startedAt : undefined,
    });
  }

  // ── Agent actions ──────────────────────────────────────────────────────────

  // Attests the agent's decision to invoke a tool (before the tool runs).
  override async handleAgentAction(action: AgentAction): Promise<void> {
    this.attest('agent-action', {
      tool: action.tool,
      toolInput: action.toolInput,
    });
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function modelName(serialized: Serialized): string {
  // LangChain serialized IDs are hierarchical: last segment is the class name.
  return serialized.id?.at(-1) ?? 'unknown';
}

function toolName(serialized: Serialized): string {
  return (serialized as { name?: string }).name ?? serialized.id?.at(-1) ?? 'unknown';
}
