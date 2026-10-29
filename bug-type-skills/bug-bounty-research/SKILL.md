---
name: bug-bounty-research
description: Turn public bug-bounty reports and product behavior into practical, target-specific testing ideas for authorized programs. Use when learning from disclosed reports, choosing what to test next, understanding why a past finding worked, building a safe test plan, or routing work to a vulnerability-specific skill. Do not use as a link collector or payload list.
---

# Learn From Bug-Bounty Reports

## Purpose

Read reports to recover the hunter's thinking, then turn that thinking into the next safe test. The output should be a short playbook, not a list of links, copied payloads, or technical summaries.

Use only on assets covered by a current bug-bounty or vulnerability-disclosure policy. Follow the program's scope, rate limits, automation limits, and prohibited-action rules.

## The Six Questions

For every useful report, answer these in plain language:

1. **What feature did the hunter choose?** Name the product action, such as project import, account linking, gift-card redemption, GraphQL search, or MFA enrollment.
2. **What looked wrong?** Identify the clue: two routes behaved differently, a hidden field was accepted, an old session survived, a background job trusted earlier state, or two parsers disagreed.
3. **What assumption failed?** Write the broken promise in one sentence. Example: "Enabling MFA should retire sessions that never passed MFA."
4. **What did the hunter change?** Record the single useful mutation: destination type, object owner, callback form, timing, API path, field shape, or session age.
5. **How was impact proved?** Prefer a victim-side state change, clean-session access, durable balance change, controlled callback, or cross-account data difference.
6. **Where else could the same mistake exist?** List sibling features that reuse the same model, worker, serializer, parser, cache policy, or identity mapping.

Ignore product-specific trivia unless it changes one of those answers.

## Turn the Lesson Into a Test

Write each idea in this form:

> In **feature**, the system may trust **assumption**. Compare **normal case** with **one changed condition** and confirm using **controlled evidence**.

Example:

> In project import, the system may accept model fields that the UI never exposes. Export a controlled project, add one harmless field supported by the model, re-import it, and watch for the field's documented callback or stored result.

Then create five items:

- **Baseline:** the normal request and expected result.
- **One change:** exactly one actor, object, state, route, parser, or timing difference.
- **Negative control:** a case that should not create the result.
- **Proof:** the safest observable that shows a real boundary was crossed.
- **Stop point:** the first result that proves the issue without touching unrelated users or data.

## Prefer Comparisons Over Payload Lists

Strong hunters repeatedly compare things the product claims are equivalent:

- web versus mobile versus API;
- REST versus GraphQL;
- direct lookup versus nested lookup;
- owner versus member versus removed member;
- user-owned versus group-owned destination;
- preview versus background delivery;
- old session versus new session;
- sequential request versus synchronized duplicate;
- cache view versus origin view;
- validator interpretation versus final parser interpretation.

Change one fact at a time. If several facts change, the result will not explain which assumption failed.

## Proof Standard

A report-quality result shows:

- what the system promised;
- the smallest change that broke the promise;
- a controlled account, object, file, callback, or balance that proves it;
- a negative control that rules out normal behavior;
- the lasting security or business effect;
- the wider family of features that may share the same root cause.

Do not treat an error, unusual status code, reflection, timing spike, missing client-side control, or accepted input as proof by itself.

## Safety

- Use accounts, tenants, objects, files, payment value, inboxes, and callback servers you control.
- Keep concurrency and resource tests small.
- Do not collect unrelated user data, claim third-party resources, persist access, send spam, or degrade availability.
- Stop when the controlled proof establishes the boundary failure.
- Separate demonstrated impact from a possible follow-on that you did not test.

## Using the Bug-Type Skills

After the report lesson produces a concrete idea, switch to the matching bug-type skill and carry forward the baseline, one change, negative control, proof, and stop point. Do not restart with generic enumeration.

Read `references/report-derived-patterns.md` for worked examples showing how real reports became reusable hunting methods. Read `references/hypothesis-led-testing.md` only when a result is ambiguous or a complex state matrix is needed.
