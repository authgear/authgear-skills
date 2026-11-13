# Authgear Skills

Installable skills for AI coding agents ([Cursor](https://cursor.com), [Claude Code](https://claude.ai), [Codex](https://codex.dev), [OpenCode](https://opencode.dev), [Gemini CLI](https://ai.google.dev/gemini-api/docs), and similar) to integrate [Authgear](https://www.authgear.com/) into your projects.

## Skills

- **authgear-integration** (`skills/authgear-integration/`) — Integrate Authgear authentication into web, mobile, and backend applications:
  - **Frontend/Mobile**: React, React Native, Flutter, Android, Vue, Next.js with SDK setup, login/logout flows, protected routes, user providers
  - **Backend**: Python, Node.js, Go, Java, PHP, ASP.NET with JWT validation, API authentication, user verification
- **authgear-build-custom-ui** (`skills/authgear-build-custom-ui/`) — Build a Custom UI (login / signup / forgot-password pages) on the Authentication Flow API from your `authentication_flow` YAML, deploy it, and update it when the YAML changes:
  - **Frameworks**: React (SPA)
  - **Deploy targets**: Cloudflare

## Installation

Install with [`npx skills`](https://github.com/vercel-labs/skills):

```bash
# All skills
npx skills add authgear/authgear-skills

# A single skill
npx skills add authgear/authgear-skills --skill authgear-integration
npx skills add authgear/authgear-skills --skill authgear-build-custom-ui
```

Or point your agent's skills path at this repo (or copy a folder from `skills/`).

## Usage

Once installed, just ask your agent, e.g. "add Authgear login to my React app" (authgear-integration) or "build a custom UI for my Authgear authentication flow" (authgear-build-custom-ui). The agent picks the matching skill.

## Structure

```
skills/
  authgear-integration/   # Authgear integration skill
    SKILL.md
    assets/
    references/
  authgear-build-custom-ui/  # Custom UI (Authentication Flow API) skill
    SKILL.md
    references/           # links to upstream specs/source + errata; frameworks/, deploy/
```
