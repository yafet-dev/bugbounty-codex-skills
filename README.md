# Bug Bounty Codex Skills

This repository contains Codex skills for bug bounty research workflows. The
skills are built from patterns observed in the public top HackerOne reports by
bug type, with the first 50 public list entries used as the main learning set
for each category when available.

Source list:

- https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/

Publicly accessible disclosed reports were used where available. Private,
removed, unavailable, or non-applicable reports were skipped. The skills
summarize methodology and recurring vulnerability patterns; they do not copy
full reports, include exploitation scripts, or include report-writing workflows.

## Structure

Each skill lives under `bug-type-skills/<skill-name>/`:

- `SKILL.md`: the main Codex skill guide.
- `references/advanced-methodology.md`: deeper testing notes and pattern memory.
- `agents/openai.yaml`: agent metadata for the skill.

## Skills

| Skill | Focus |
| --- | --- |
| `account-takeover` | Account takeover chains, recovery abuse, token theft, session compromise, and linked-account takeover paths. |
| `api-hacking` | API-specific attack surfaces including exposed APIs, leaked keys, undocumented operations, GraphQL, and mobile/internal API behavior. |
| `auth-hacking` | Broken authentication, login bypasses, weak session handling, 2FA gaps, and auth flow abuse. |
| `authorization-bypass` | Privilege escalation, cross-tenant access, role bypass, admin exposure, and object-level access failures. |
| `business-logic` | Workflow abuse, payment/order manipulation, state-machine flaws, reward abuse, and process bypasses. |
| `clickjacking` | UI redress risks, framing-sensitive actions, OAuth/login consent framing, and account-impacting click paths. |
| `csrf` | State-changing request forgery, login CSRF, linked-account abuse, token leakage chains, and weak anti-CSRF defenses. |
| `dos` | Application-layer denial of service, expensive operations, cache poisoning, GraphQL batching, and amplification paths. |
| `file-reading` | Local/remote file disclosure, traversal, backup exposure, archive extraction, and misconfigured file serving. |
| `file-upload` | Upload validation bypass, stored content execution, parser abuse, media conversion flaws, and cloud upload exposure. |
| `graphql` | GraphQL authorization, introspection, batching, aliasing, mutation abuse, schema leaks, and resolver behavior. |
| `idor` | Insecure direct object references across CRUD, GraphQL variables, tenant selectors, billing objects, files, tickets, and media. |
| `information-disclosure` | Sensitive data exposure, private metadata leaks, debug output, internal data, tokens, PII, and unintended API responses. |
| `mfa-bypass` | MFA enrollment, reset, recovery, downgrade, enforcement, and verification bypasses. |
| `mobile-security` | Android/iOS app issues, deep links, intents, token storage, mobile API trust assumptions, and platform-specific flows. |
| `oauth` | OAuth redirect, code/token leakage, callback validation, consent abuse, linked-account flaws, and provider trust errors. |
| `openid-sso` | OpenID Connect, SAML, SSO domain enforcement, email verification trust, provisioning, and assertion handling. |
| `open-redirect` | Redirect abuse that enables token theft, OAuth compromise, phishing, auth bypass, and chaining into higher impact. |
| `race-condition` | Concurrent workflow abuse, double spend, invite/reward duplication, state transition races, and TOCTOU flaws. |
| `rce` | Remote code execution paths through exposed services, admin panels, upload chains, injection, CI/CD, and internal tools. |
| `request-smuggling` | HTTP desync, proxy/front-end mismatch, auth bypass, cache poisoning, request queue poisoning, and session theft chains. |
| `sqli` | SQL injection in APIs, admin tools, search, GraphQL-backed data access, blind extraction, and impact escalation. |
| `ssrf` | Blind SSRF, cloud metadata access, internal service reachability, preview/export/fetch APIs, and protocol abuse. |
| `ssti` | Server-side template injection, expression evaluation, sandbox escape, email/template editors, and rendering pipelines. |
| `subdomain-takeover` | Dangling DNS, cloud service claims, takeover-to-auth-bypass chains, and domain trust abuse. |
| `web-cache` | Cache deception, cache poisoning, CORS/cache interaction, sensitive response caching, and stored payload delivery. |
| `xss` | Reflected, stored, DOM, blind, CSP bypass, token theft, admin-context payloads, and account-impacting XSS chains. |
| `xxe` | XML external entity issues, parser configuration, file disclosure, SSRF, blind exfiltration, and XML upload/import surfaces. |

## Use

Install or copy the desired skill folders into the Codex skills directory used
by your environment, then invoke the relevant skill by name when you want Codex
to apply that bug-type methodology.

These are research and testing guides. Use them only on systems where you have
permission to test.
