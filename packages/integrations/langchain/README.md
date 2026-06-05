# @vane.build/langchain

LangChain callback handler that sends a signed, tamper-evident attestation record to [Vane](https://vane.build) for every LLM call, tool invocation, and agent action. Node 18+.

## Installation

```bash
npm install @vane.build/langchain
```

Peer dependency: `@langchain/core >=0.2.0`

## Usage

```typescript
import { ChatOpenAI } from '@langchain/openai';
import { VaneCallbackHandler } from '@vane.build/langchain';

const vane = new VaneCallbackHandler({
  baseUrl: 'https://api.vane.build',
  apiKey: process.env.VANE_API_KEY!,
  agentId: 'contract-reviewer',
});

const llm = new ChatOpenAI({ callbacks: [vane] });
await llm.invoke('Summarise this contract.');
// → one "llm-call" record written to the Vane chain
```

Attach the same handler to a full agent executor:

```typescript
import { createReactAgent } from '@langchain/langgraph/prebuilt';
import { TavilySearchResults } from '@langchain/community/tools/tavily_search';
import { VaneCallbackHandler } from '@vane.build/langchain';

const vane = new VaneCallbackHandler({
  baseUrl: 'https://api.vane.build',
  apiKey: process.env.VANE_API_KEY!,
  agentId: 'research-agent',
});

const agent = createReactAgent({
  llm: new ChatOpenAI({ callbacks: [vane] }),
  tools: [new TavilySearchResults()],
});

await agent.invoke(
  { messages: [{ role: 'user', content: 'What is the current EU AI Act status?' }] },
  { callbacks: [vane] },
);
// → one "llm-call" + one "agent-action" + one "tool-call" record per turn
```

## Constructor options

```typescript
new VaneCallbackHandler({
  baseUrl:   string;  // Vane API base URL, e.g. https://api.vane.build
  apiKey:    string;  // Bearer token (Vane API key)
  agentId:   string;  // Appears on every attestation record
  companyId?: string; // If omitted, the API key's company is used
})
```

## What gets attested

| Event | `actionType` | Key payload fields |
|---|---|---|
| LLM call complete | `llm-call` | `model`, `input`, `output`, `tokenUsage`, `durationMs` |
| Tool call complete | `tool-call` | `tool`, `input`, `output`, `durationMs` |
| Agent picks a tool | `agent-action` | `tool`, `toolInput` |

Attestation is fire-and-forget. A failure to reach the Vane API logs to `console.error` and never interrupts agent execution.

---

[Vane main repo](https://github.com/vane-build/vane) · [docs.vane.build/integrations/langchain](https://docs.vane.build/integrations/langchain)
