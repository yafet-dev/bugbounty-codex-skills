# Bug Bounty Codex Skills

This repository contains practical Codex skills for authorized bug-bounty
research. The skills do not merely point to public reports. They extract the
hunter's reasoning and turn it into a repeatable playbook: what feature to
choose, what clue to notice, which assumption to challenge, what single change
to test, how to prove impact safely, and where the same root cause may repeat.

Every vulnerability-specific skill has a plain-language, report-derived
starting point in `SKILL.md` and a deeper worked playbook at the top of
`references/advanced-methodology.md`. Direct report links and reading lists were
removed from those playbooks so the methodology stands on its own.

## Structure

Each skill lives under `bug-type-skills/<skill-name>/`:

- `SKILL.md`: the main Codex skill guide.
- `references/advanced-methodology.md`: deeper testing notes and pattern memory.
- `agents/openai.yaml`: agent metadata for the skill.

`bug-type-skills/bug-bounty-research/` additionally contains:

- `references/report-derived-patterns.md`: worked examples that turn real reports into reusable hunting methods.
- `references/hypothesis-led-testing.md`: target modeling, experiment matrices, confirmation ladders, and chain analysis.

`bug-type-skills/elite-bug-bounty-hunting/` is the architecture-driven orchestration skill. It routes among focused references for research refresh, code-to-runtime analysis, identity and authorization, server-side primitives, state and business logic, parser/cache/edge behavior, client-side delivery, exploit-chain validation, and PoC evidence. Its scripts operate only on local researcher-authored ledgers and saved evidence; they do not scan targets.

## Skills

| Skill | Focus |
| --- | --- |
| `account-takeover` | Account takeover chains, recovery abuse, token theft, session compromise, and linked-account takeover paths. |
| `api-hacking` | API-specific attack surfaces including exposed APIs, leaked keys, undocumented operations, GraphQL, and mobile/internal API behavior. |
| `auth-hacking` | Broken authentication, login bypasses, weak session handling, 2FA gaps, and auth flow abuse. |
| `authorization-bypass` | Privilege escalation, cross-tenant access, role bypass, admin exposure, and object-level access failures. |
| `bug-bounty-research` | Live report and original-research mining, scope modeling, hypothesis generation, differential experiments, confirmation, and skill routing. |
| `business-logic` | Workflow abuse, payment/order manipulation, state-machine flaws, reward abuse, and process bypasses. |
| `clickjacking` | UI redress risks, framing-sensitive actions, OAuth/login consent framing, and account-impacting click paths. |
| `csrf` | State-changing request forgery, login CSRF, linked-account abuse, token leakage chains, and weak anti-CSRF defenses. |
| `dos` | Application-layer denial of service, expensive operations, cache poisoning, GraphQL batching, and amplification paths. |
| `elite-bug-bounty-hunting` | Architecture-adaptive, research-driven hunting for reproducible high-impact vulnerabilities and verified exploit chains, with strict scope and evidence gates. |
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
| `waf-parser-differentials` | WAF, proxy, framework, and sink parsing disagreements involving encodings, charsets, structured bodies, duplicate parameters, and URL normalization. |
| `xss` | Reflected, stored, DOM, blind, CSP bypass, token theft, admin-context payloads, and account-impacting XSS chains. |
| `xxe` | XML external entity issues, parser configuration, file disclosure, SSRF, blind exfiltration, and XML upload/import surfaces. |

## Use

Install or copy the desired skill folders into the Codex skills directory used
by your environment, then invoke the relevant skill by name when you want Codex
to apply that bug-type methodology.

For a focused report-learning pass, invoke `$bug-bounty-research`. For an
architecture-driven engagement that combines live research, code analysis,
manual testing, chain validation, and evidence production, invoke
`$elite-bug-bounty-hunting`. Establish a normal baseline, change one condition,
use a negative control, and stop after the smallest controlled proof.

These are research and testing guides. Use them only on systems where you have
permission to test.
