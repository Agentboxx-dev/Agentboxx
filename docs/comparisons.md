# How Agentboxx compares to LangSmith, Langfuse and E2B

People often ask whether Agentboxx replaces an observability platform such as
[LangSmith](https://www.langchain.com/langsmith) or [Langfuse](https://langfuse.com), or a cloud
sandbox such as [E2B](https://e2b.dev) (or Modal). Short answer: it does a different job, and it
works next to them.

This page describes what Agentboxx does today, and what these tools are generally built for. The
other products change quickly. Check their own documentation for their current features, and
[open an issue](https://github.com/Agentboxx-dev/Agentboxx/issues) if something here is out of date.

## The core distinction

**Observability platforms trace from inside the agent.** LangSmith and Langfuse work through an SDK
or callback in the agent's own process. The agent (or its framework) reports what happened: prompts,
model responses, tool calls, latency, token cost. That is very useful for debugging, evaluation and
cost tracking. But the record is produced by the process being observed, so it is only as trustworthy
as that process.

**Cloud sandboxes isolate where the code runs.** E2B and similar services give an agent a remote
environment to execute code in. They answer "where does the agent's code run, and how far can it
reach?". Whether the sandbox also gives you a record you can hand to a third party is a separate
question, and not what a sandbox is for.

**Agentboxx records from outside, on the host.** The host runs the command and captures the output,
exit code and timing itself, instead of trusting the agent's account of them. Each record is
hash-chained and HMAC-signed with a key that never enters the sandbox, and a run can also close with
an Ed25519 receipt that others can check with only the public key. If a record is edited, removed or
reordered afterward, `agentbox verify` reports it. See the [log format](log-format.md) and
[verification](verification.md).

One limit applies throughout: a signature shows who vouched for a record and that it has not changed.
It does not show that the work was correct, and it cannot cover anything that bypassed the recorder.

## Feature matrix

"Yes" for Agentboxx means the repository implements it today. For the other tools, the column
describes what they are mainly built for, not an exhaustive feature list.

| | Agentboxx | LangSmith / Langfuse | E2B (cloud sandbox) |
|---|---|---|---|
| **Main job** | Independent, signed record of what an agent did | Tracing, evaluation and cost tracking for LLM apps | A remote environment to run agent code |
| **Where the record is made** | On the host, outside the agent and its sandbox | Inside the agent process, through an SDK or callbacks | Not its purpose |
| **Tamper-evidence** | Yes: hash chain, HMAC signatures and a signed closing manifest | Not their main focus | Not their main focus |
| **Offline verification** | Yes: `agentbox verify`, signed bundles (`agentbox bundle`), a standalone verifier, public-key receipts | Not their main focus | Not their main focus |
| **Host-side assertions** | Yes: task contracts with file and command assertions run by the host, with a signed verdict | Evaluation runs on recorded traces or datasets | No |
| **Sandboxing** | Yes, with the Docker backend (no network by default, read-only root, dropped capabilities, resource limits). The local backend has no isolation | No: it observes, it does not run code | Yes: the core of the product, remote and managed |
| **Loop detection with hints to the agent** | Yes: repeated command, repeated error, no progress and cycles | Not their main focus | No |
| **Prompts, model responses, token cost, dashboards** | No | Yes | No |
| **Secrets removed before the record is written** | Yes, before signing | Check the vendor's masking and redaction options | Not applicable |
| **Where it runs** | Your machine or server; no hosted service needed | Mainly a hosted service; some offer self-hosting, check each vendor | Mainly a hosted service; check the vendor for self-hosting |

## Using them together

They do not compete for the same slot, so you can combine them.

- **With Langfuse or LangSmith.** Keep the platform for traces, prompt versions, evaluations and
  cost. Add Agentboxx for the part you may need to defend later: what commands actually ran, what
  they printed, whether the workspace changed, and whether the task assertions passed. Agentboxx
  already records LangChain tool executions through
  [`AgentboxxCallbackHandler`](../README.md#langchain--langgraph-integration), so a LangChain agent
  can send traces to the platform and signed tool-call records to Agentboxx at the same time. To
  line the two up, use the same session or run identifier in both places.
- **With OpenTelemetry.** Agentboxx does not export OpenTelemetry yet; it is on the
  [roadmap](architecture.md). Today the signed log is NDJSON, and `agentbox report --format json`
  gives a machine-readable summary you can load into whatever you already use.
- **With E2B, Modal or another cloud sandbox.** Agentboxx's own sandbox is a local Docker
  container. If you need remote or managed isolation, the cloud sandbox can be the place where your
  agent's code runs. Agentboxx is designed so that the recorder and the signing key stay on a host
  the agent cannot reach, so keep that rule if you combine them. Running Agentboxx's recorder
  inside the same remote sandbox as the agent would give up the property that makes its records
  worth checking.

## When to choose which

- You want to debug prompts, compare model versions or watch spend: use an observability platform.
- You need to run untrusted code away from your own machine, at scale, without managing
  infrastructure: use a cloud sandbox.
- You need a record of what an agent did that an auditor, a customer or a future you can verify
  without trusting the agent or your own database: use Agentboxx.
- Often the honest answer is more than one of these.
