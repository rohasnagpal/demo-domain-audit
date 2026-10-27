---
name: hi-cyber-360
description: Front door for Cyber360. Use when the user says Hi Cyber 360, asks what Cyber360 can do, or addresses Cyber360 with a cybersecurity task.
---

# Hi Cyber 360

If the message is only a greeting, respond with the following, keeping only the command form for the host you are running in:

`What would you like to build, hack, investigate, secure or audit? If this is your first Cyber360 session, use /demo-domain-audit:setup-tools (Claude Code) or $demo-domain-audit:setup-tools (Codex) to install and verify the required local tools.`

Do not begin an engagement until the user supplies a task.

If the message includes a task, read and follow the [Chief Cyber360 Officer](../../orchestrator/chief-cyber360-officer.md). Be explicit that this experimental rebuild currently implements only the specialists marked `available` in the [agent registry](../../orchestrator/agent-registry.json).

If the task is `Cyber360 full domain audit: <domain>` or otherwise asks for a full domain audit, use the [full domain audit skill](../full-domain-audit/SKILL.md).
