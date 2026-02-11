# Authgear Skills

Installable skills for AI coding agents ([Cursor](https://cursor.com), [Claude Code](https://claude.ai), [Codex](https://codex.dev), [OpenCode](https://opencode.dev), [Gemini CLI](https://ai.google.dev/gemini-api/docs), and similar) to integrate [Authgear](https://www.authgear.com/) into your projects.

## Skills

- **authgear-integration** (`skills/authgear-integration/`) — Integrate Authgear authentication into web, mobile, and backend applications:
  - **Frontend/Mobile**: React, React Native, Flutter, Android, Vue, Next.js with SDK setup, login/logout flows, protected routes, user providers
  - **Backend**: Python, Node.js, Go, Java, PHP, ASP.NET with JWT validation, API authentication, user verification

## Usage

Point your agent’s skills path at this repo (or the `skills` folder)—e.g. in Cursor, Claude Code, Codex, OpenCode, Gemini CLI, or similar—so the agent can use these skills when you ask about Authgear or adding authentication.

## Structure

```
skills/
  authgear-integration/   # Authgear integration skill
    SKILL.md
    assets/
    references/
```
