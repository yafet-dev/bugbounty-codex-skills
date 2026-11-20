---
name: bug-bounty-skill-creator
description: Create a new Codex skill or update an existing one, especially bug bounty skills that follow this repo's layout. Use when someone wants to write, fix, or check a skill. Not for hunting bugs yourself.
license: Apache-2.0 (see license.txt and NOTICE)
metadata:
  short-description: Create, update, and check skills
---

# Bug Bounty Skill Creator

Use this to write a new skill or clean up an old one. A good skill tells Codex the things it wouldn't figure out on its own, and nothing more.

## The basics

- **Codex is already smart.** Only write things that change what it does or make its work better. Cut generic advice, repeated rules, "what if" edge cases, and examples that don't teach anything.
- **Stick to what the user asked for.** A skill helps with a task. It shouldn't take over the task, make the job bigger, touch unrelated settings, or hint that Codex is allowed to do more than it was asked. Don't turn one example or one past mistake into a rule for everything.
- **Be strict only where it matters.** If there are a few good ways to do something, describe the goal and let Codex choose. Use exact steps, scripts, or "always" and "never" only when getting it wrong would really hurt: safety, permissions, or a fragile workflow.
- **Make the skill easy to pick.** Codex sees the name and description before it opens a skill. Say what the skill does and when to use it. Don't list everything it could ever do, and don't write a catch-all that grabs unrelated requests.
- **Load detail only when it's needed.** Keep the main points in `SKILL.md`. Move long, situation-specific material (schemas, big examples, step-by-step guides) into `references/`, and read only the file that fits the task. A small skill doesn't need extra files.

Being allowed to do a task doesn't mean being allowed to do more. If a skill retries things or changes anything outside the workspace, give it a clear point where it stops.

## What a skill looks like

```text
skill-name/
|-- SKILL.md            Required. Frontmatter (name, description) plus the instructions
|-- agents/openai.yaml  Optional. UI name, short blurb, default prompt, invocation policy
|-- references/         Optional. Docs that are read only when needed
|-- scripts/            Optional. Helper code that runs instead of being rewritten each time
`-- assets/             Optional. Files that go into the output (templates, images, fonts)
```

Only add folders and files the skill really uses. No placeholder files, and no README, changelog, or install guide inside the skill folder.

### SKILL.md

- **Frontmatter:** `name` and `description` are required. Keep any existing `metadata` or other supported fields.
- **Description:** In a sentence or two, say what the skill does and when to use it. Add a "not for X" note only when people would likely pick it by mistake. 1024 characters max, and no angle brackets.
- **Body:** The goal, the main workflow, the real rules, and links to references. Keep it as short as the job allows.

Codex reads a skill in three layers:

1. **Name and description:** always visible, used to decide whether to pick the skill.
2. **`SKILL.md` body:** read once the skill is picked.
3. **References and scripts:** opened only when the task needs them.

### references/

For docs that only matter some of the time: a schema, API notes, or a deep dive on one attack type. Link each file from `SKILL.md` and say when to read it, for example: "For SAML, read `references/saml.md`."

Don't put the same information in two places, and don't paste whole manuals or tutorials Codex already knows. If a reference file is long, start it with a short list of what's inside.

### scripts/

Add a script when the same code would otherwise be rewritten every time, or when running fixed code is a lot more reliable. Run every script you add or change to make sure it works.

In this repo, scripts must only work on local files, like notes, saved requests, or evidence. They must never scan, attack, or send traffic to a target.

### assets/

Files that end up in the output rather than in the instructions: templates, images, fonts. Don't read them as instructions unless the task needs it.

### agents/openai.yaml

This holds UI info: `display_name`, `short_description` (25 to 64 characters), `default_prompt` (mention the skill as `$skill-name`), and an optional `policy`. For every field, read [references/openai_yaml.md](references/openai_yaml.md).

Codex can pick skills on its own by default. Only turn that off if the user asks for a skill that runs only when called by name:

```yaml
policy:
  allow_implicit_invocation: false
```

Don't turn it off just because a skill does something sensitive. Keep the skill easy to find, and ask for approval right before the risky step. Keep an existing skill's policy unless the user asks to change it.

## Creating or updating a skill

Match the effort to the request. A big new skill might mean thinking through real use cases, choosing resources, setting up files, writing, and checking. A small fix might be one edit and a validator run.

Only ask questions when the missing information matters and you can't make a reasonable guess. If the user gave a location, use it. Otherwise:

- **In this repo:** put the skill in `bug-type-skills/<skill-name>/`.
- **Anywhere else:** use `$CODEX_HOME/skills`, or `~/.codex/skills` if `CODEX_HOME` isn't set.

### Naming

- Use lowercase letters, numbers, and hyphens. Keep it under 64 characters.
- Keep it short and clear. In this repo, name it after the bug type or workflow, like `idor`, `web-cache`, or `race-condition`.
- The folder name must match the skill name.

### Start a new skill

The scripts need Python 3. The validator, and the yaml generator when it reads the name from `SKILL.md`, also need PyYAML (`pip install pyyaml`). Run them with `python` in front, which also works on Windows.

```bash
python scripts/init_skill.py <skill-name> --path <output-folder> [--resources scripts,references,assets] [--examples]
```

For example, to add a new bug type to this repo from the repo root:

```bash
python bug-type-skills/bug-bounty-skill-creator/scripts/init_skill.py web-cache --path bug-type-skills --resources references
```

This creates the folder, a starter `SKILL.md`, and `agents/openai.yaml`. Only ask for the resource folders you'll actually use. `--examples` adds placeholder files; replace or delete them before you finish. Don't run it on a skill that already exists.

To make only `agents/openai.yaml`:

```bash
python scripts/generate_openai_yaml.py <path/to/skill> --interface 'short_description=Short UI label' --interface 'default_prompt=Use $skill-name to ...'
```

Keep the single quotes so your shell doesn't treat `$skill-name` as a variable. This rewrites the whole file, so if it already has `policy` or `dependencies`, edit it by hand instead.

### Write the instructions

Write only what another Codex needs to do the job well: the goal, the context it wouldn't guess, the real rules, and which references or scripts to use. Respect the user's choices and permission limits. Don't force a fixed number of steps or a set structure unless the task really needs one.

For bug bounty skills in this repo, also:

- Look at a similar skill first (for example `bug-type-skills/idor/`) and follow its shape: `SKILL.md`, `agents/openai.yaml`, and `references/advanced-methodology.md`.
- Start `SKILL.md` with a short "Report-Derived Starting Point": the one test that most often finds this bug.
- Focus on how to think and test: where the bug hides, what to change, how to confirm it safely, and how to show real impact.
- Remind the reader to test only what they're allowed to test, and to stop at the smallest proof that shows the bug.
- Summarize patterns from public reports in your own words. Don't copy whole reports, payload dumps, or reading lists.
- Add a row for the new skill to the table in the repo's `README.md`.

### Check your work

```bash
python scripts/quick_validate.py <path/to/skill>
```

This checks the frontmatter, the name, and leftover `[TODO: ...]` placeholders. It can't tell you whether the skill is actually good, so also check that:

- the description makes it clear when to use the skill,
- the instructions don't go further than the user wants,
- every reference file is linked from somewhere,
- any scripts actually run.

If you add tests, test what the code really does, not exact wording or headings.

Improve skills based on real use and real mistakes. A small, targeted fix beats piling on new rules.

## Trying it out with a fresh agent

For a big or risky skill, it can help to have a separate subagent try it on a realistic request, if you're allowed to use subagents. Small edits don't need this.

Give the tester a realistic request, the skill, and only the files it needs. Don't tell it the expected answer, the bug you suspect, or the fix you have in mind. For example:

```text
Use $skill-name at /path/to/skill-name to handle this request: ...
```

Run the test in a throwaway folder so its files don't end up in the repo, and keep it away from anything live. Ask first if it would need extra permissions, touch a real system, or take a lot of time or money. Then look at what actually happened, and change only what the results back up.
