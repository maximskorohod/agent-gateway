# AgentKeyGate plugin for Claude Code

The plugin connects Claude Code to your self-hosted [AgentKeyGate](https://github.com/maximskorohod/agentkeygate) gateway over Streamable HTTP at `/mcp`. After the connection Claude Code sees the gateway tools: `list_services`, `request_access`, `check_request` and `call`. It asks for a time-limited pass instead of your API key, and the key itself never leaves the gateway. The plugin also ships the `agentkeygate` skill with step-by-step instructions and a helper script.

## Install

Add the marketplace, install the plugin, then set the two settings with `/plugin configure agentkeygate@agentkeygate` in Claude Code:

```bash
claude plugin marketplace add maximskorohod/agentkeygate
claude plugin install agentkeygate@agentkeygate
```

Settings:

- `mcp_url`: the full MCP address of your gateway, for example `https://your-domain/mcp`;
- `agent_token`: the agent token (`gwa_...`) that the owner created in the gateway web UI under Agents. It is shown once when the agent is created. The value is marked sensitive and is sent as a Bearer authorization header.

To verify the installation, run `claude mcp list` and look for `agentkeygate`, then ask Claude Code to list the services available through agentkeygate.

To remove the plugin, run `claude plugin uninstall agentkeygate` and revoke the agent in the gateway web UI.
