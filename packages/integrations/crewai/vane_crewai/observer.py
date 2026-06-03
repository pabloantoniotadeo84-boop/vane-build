"""
VaneObserver — wraps a CrewAI Crew to attest every agent action and
task completion to the Vane attestation API.
"""

from __future__ import annotations

import json
import threading
import urllib.request
import urllib.error
from typing import Any, Callable, Optional


class VaneObserver:
    """
    Wraps a CrewAI Crew so every agent step and task completion is attested
    to Vane. Uses background threads for HTTP calls — never blocks the crew.

    Usage (three lines):
        from vane_crewai import VaneObserver
        observer = VaneObserver(base_url="...", api_key="...", agent_id="...")
        crew = observer.wrap(crew)
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        agent_id: str,
        company_id: str = "",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.company_id = company_id

    # ── Public API ────────────────────────────────────────────────────────────

    def wrap(self, crew: Any) -> Any:
        """
        Attach attestation callbacks to *crew* and return it.
        Preserves any existing step_callback and task_callback the crew
        already has — both will still be called.
        """
        prior_step_cb: Optional[Callable[..., Any]] = getattr(crew, "step_callback", None)
        prior_task_cb: Optional[Callable[..., Any]] = getattr(crew, "task_callback", None)

        crew.step_callback = self._make_step_callback(prior_step_cb)
        crew.task_callback = self._make_task_callback(prior_task_cb)
        return crew

    # ── Callback factories ────────────────────────────────────────────────────

    def _make_step_callback(
        self,
        prior: Optional[Callable[..., Any]],
    ) -> Callable[..., Any]:
        observer = self

        def step_callback(step_output: Any) -> None:
            # step_output is AgentStep (has .action and .observation) or
            # AgentFinish (has .return_values) or a plain dict — be defensive.
            action_type = "agent-step"
            payload: dict[str, Any] = {}

            action = getattr(step_output, "action", None)
            observation = getattr(step_output, "observation", None)
            return_values = getattr(step_output, "return_values", None)

            if action is not None:
                # AgentAction: tool name + input
                action_type = "tool-call"
                payload = {
                    "tool": getattr(action, "tool", str(action)),
                    "toolInput": getattr(action, "tool_input", None),
                    "observation": str(observation) if observation is not None else None,
                }
            elif return_values is not None:
                # AgentFinish: final answer from this agent
                action_type = "agent-finish"
                payload = {"output": return_values}
            else:
                payload = {"raw": _safe_str(step_output)}

            observer._attest_async(action_type, payload)

            if prior is not None:
                prior(step_output)

        return step_callback

    def _make_task_callback(
        self,
        prior: Optional[Callable[..., Any]],
    ) -> Callable[..., Any]:
        observer = self

        def task_callback(task_output: Any) -> None:
            # task_output is TaskOutput (crewai.tasks.task_output.TaskOutput)
            payload: dict[str, Any] = {
                "description": getattr(task_output, "description", None),
                "agent": getattr(task_output, "agent", None),
                "output": getattr(task_output, "raw", _safe_str(task_output)),
            }
            observer._attest_async("task-complete", payload)

            if prior is not None:
                prior(task_output)

        return task_callback

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _attest_async(self, action_type: str, payload: dict[str, Any]) -> None:
        """Send an attestation in a daemon thread — never blocks the caller."""
        thread = threading.Thread(
            target=self._attest,
            args=(action_type, payload),
            daemon=True,
        )
        thread.start()

    def _attest(self, action_type: str, payload: dict[str, Any]) -> None:
        body = json.dumps(
            {
                "agentId": self.agent_id,
                "companyId": self.company_id,
                "actionType": action_type,
                "payload": payload,
            }
        ).encode()

        req = urllib.request.Request(
            f"{self.base_url}/v1/attest",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception as exc:  # noqa: BLE001
            # Attestation failures must never crash the crew.
            print(f"[Vane] attest failed: {exc}")


def _safe_str(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str)
    except Exception:  # noqa: BLE001
        return str(obj)
