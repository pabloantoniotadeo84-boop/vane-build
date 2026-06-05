# @vane.build/openai-agents

OpenAI Agents SDK hooks that send a signed, tamper-evident attestation record to [Vane](https://vane.build) for every tool call, agent lifecycle event, and handoff. Node 18+.

## Installation

```bash
npm install @vane.build/openai-agents
```

Peer dependency: `@openai/agents >=0.0.1`

## Usage

```typescript
import { Agent, run } from '@openai/agents';
import { createVaneHooks } from '@vane.build/openai-agents';

const agent = new Agent({
  name: 'contract-reviewer',
  instructions: 'Review the provided contract and identify key risk clauses.',
});

const hooks = createVaneHooks({
  baseUrl: 'https://api.vane.build',
  apiKey: process.env.VANE_API_KEY!,
  agentId: 'contract-reviewer',
});

const result = await run(agent, 'Review this contract.', { hooks });
console.log(result.finalOutput);
```

Multi-agent with handoffs — pass the same hooks to every `run()` call:

```typescript
import { Agent, run } from '@openai/agents';
import { createVaneHooks } from '@vane.build/openai-agents';

const hooks = createVaneHooks({
  baseUrl: 'https://api.vane.build',
  apiKey: process.env.VANE_API_KEY!,
  agentId: 'orchestrator',
});

const researcher = new Agent({ name: 'researcher', /* ... */ });
const writer = new Agent({ name: 'writer', handoffDescription: 'Drafts the report', /* ... */ });
const orchestrator = new Agent({ name: 'orchestrator', agents: [researcher, writer], /* ... */ });

await run(orchestrator, 'Produce a compliance report.', { hooks });
// → agent-start, tool-call, agent-handoff, agent-end records in the Vane chain
```

## Options

```typescript
createVaneHooks({
  baseUrl:    string;  // Vane API base URL, e.g. https://api.vane.build
  apiKey:     string;  // Bearer token (Vane API key)
  agentId:    string;  // Appears on every attestation record
  companyId?: string;  // If omitted, the API key's company is used
})
```

Returns a `VaneRunHooks` object you pass as `{ hooks }` to `run()`. The type is structurally compatible with `@openai/agents` `RunHooks` — no version coupling.

## What gets attested

| Hook | `actionType` | Key payload fields |
|---|---|---|
| `onAgentStart` | `agent-start` | `agent` |
| `onAgentEnd` | `agent-end` | `agent`, `output` |
| `onToolEnd` | `tool-call` | `agent`, `tool`, `output`, `durationMs` |
| `onHandoff` | `agent-handoff` | `from`, `to` |

Attestation is fire-and-forget. A failure to reach the Vane API logs to `console.error` and never interrupts agent execution.

---

[Vane main repo](https://github.com/vane-build/vane) · [docs.vane.build/integrations/openai-agents](https://docs.vane.build/integrations/openai-agents)
