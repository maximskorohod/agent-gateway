# AgentKeyGate skill

This folder is a skill for AI agents: it teaches the agent to request short-lived, owner-approved access through an AgentKeyGate gateway and call third-party services without ever holding their API keys. The instructions live in [SKILL.md](SKILL.md), the helper script is [scripts/gw.sh](scripts/gw.sh).

## Where to put the skill

Copy or symlink this `agentkeygate` folder (the folder that contains `SKILL.md`) into the skills directory of the agent, keeping the folder name `agentkeygate`: the `name:` field in `SKILL.md` matches it.

| Agent | Skills directory |
| --- | --- |
| Claude Code | `~/.claude/skills/` |
| Codex and other agents with the common skills path | `~/.agents/skills/` |
| Cursor | `~/.cursor/skills/` |
| VS Code (Copilot) | `~/.copilot/skills/` |
| Gemini CLI | `~/.gemini/skills/` |
| Hermes | `~/.hermes/skills/` |

## Environment variables

The agent process needs two variables:

- `AGENTKEYGATE_URL`: base URL of the gateway, for example `https://gw.example.com`, no trailing slash;
- `AGENTKEYGATE_TOKEN`: the agent token (`gwa_...`) created in the gateway web UI. It is shown once when the agent is created.

The helper script `scripts/gw.sh` also needs `curl` and `jq` on the `PATH`.
