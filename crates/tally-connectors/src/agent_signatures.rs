//! Versioned, bounded process signatures. Raw command lines are never retained.
#[must_use]
pub fn identify(file: &str, command: &str) -> Option<(&'static str, String)> {
    let file = file
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(file)
        .to_ascii_lowercase();
    let cmd = command.to_ascii_lowercase();
    let name = match file.as_str() {
        "claude" | "claude.exe" => Some("Claude Code"),
        "claude desktop" | "claude.app" => Some("Claude Desktop"),
        "codex" | "codex.exe" => Some("Codex"),
        "cursor" | "cursor.exe" => Some("Cursor"),
        "windsurf" | "windsurf.exe" => Some("Windsurf"),
        "aider" | "aider.exe" => Some("Aider"),
        "gemini" | "gemini.exe" => Some("Gemini CLI"),
        "copilot" | "copilot.exe" => Some("GitHub Copilot CLI"),
        _ => None,
    };
    if let Some(name) = name {
        return Some(("agent", name.into()));
    }
    for token in cmd.split_whitespace().take(512) {
        let token = token.trim_matches(['\'', '"']);
        if (token.starts_with("@modelcontextprotocol/server-")
            || token.starts_with("@anthropic-ai/claude-code")
            || token.starts_with("@openai/codex")
            || token.starts_with("mcp-server-")
            || token.starts_with("mcp_server_"))
            && token.len() <= 160
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@/._-".contains(&b))
        {
            return Some((
                if token.contains("claude-code") || token.contains("codex") {
                    "agent"
                } else {
                    "mcp_server"
                },
                token.into(),
            ));
        }
    }
    if cmd
        .split_whitespace()
        .any(|s| matches!(s, "--mcp" | "mcp-server" | "mcp_server"))
    {
        return Some(("mcp_server", "MCP server (process signature)".into()));
    }
    for (signature, name) in [
        ("langchain", "LangChain application"),
        ("crewai", "CrewAI application"),
        ("autogen", "AutoGen application"),
    ] {
        if cmd
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|s| s == signature)
        {
            return Some(("agent", name.into()));
        }
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_never_become_labels() {
        let (_, name) = identify(
            "node",
            "npx @modelcontextprotocol/server-filesystem --token sk-secret /private/project",
        )
        .unwrap();
        assert_eq!(name, "@modelcontextprotocol/server-filesystem");
        assert!(identify("curl", "curl --token sk-secret https://example.org").is_none());
        assert!(identify("node", "npx @modelcontextprotocol/server-foo?token=secret").is_none());
    }
}
