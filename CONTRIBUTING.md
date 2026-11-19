# Contributing

Thanks for wanting to help! This guide shows you how to fix or improve a skill,
add a new one, and send your changes. It should only take a few minutes to read.
If anything here is confusing, open an issue and ask. That helps too.

## The ground rules

These matter more than anything else in this guide.

- **Authorized testing only.** Every skill is for systems you're allowed to
  test: a bug bounty program's scope, your own app, or a lab. Don't add
  anything that pushes people to test without permission.
- **Teach the method, don't copy reports.** Explain in your own words what the
  hunter noticed, what they changed, and why it worked. Don't paste full
  reports, long payload lists, or lists of report links.
- **No attack tools.** Scripts may only work on local files, like notes, saved
  requests, or evidence. Nothing that scans, attacks, or sends traffic to a
  target.
- **No real secrets or personal data.** Use made-up examples like
  `example.com`, `example.test`, fake tokens, and fake users. Never include
  real passwords, API keys, cookies, or anyone's personal info.
- **Keep it about bug bounty.** Skills here should help people find, confirm,
  or understand security bugs.

## Ways you can help

- Fix a mistake, a broken link, or a sentence that's hard to follow.
- Make an existing skill better: add a pattern you've seen work, or cut advice
  that's wrong or out of date.
- Add a skill for a bug type that's missing.
- Open an issue when you spot a problem but don't have time to fix it.

Small changes are welcome. You don't have to rewrite a whole skill to help.

## What a skill looks like

Each skill has its own folder under `bug-type-skills/`:

```text
bug-type-skills/your-skill-name/
|-- SKILL.md                            The main guide Codex reads
|-- agents/openai.yaml                  Name, short blurb, and default prompt for the Codex app
`-- references/advanced-methodology.md  Deeper notes, read only when needed
```

A few skills also have a `scripts/` folder. Only add one if your skill really
needs it, and follow the script rules below.

## Adding a new skill

1. **Check that it's not already covered.** Look at the skills table in
   [README.md](README.md). If a skill is close, improving it is often better
   than adding a new one.

2. **Fork the repo, clone your fork, and make a branch:**

   ```bash
   git checkout -b add-your-skill-name
   ```

3. **Create the starter files.** From the repo root, run:

   ```bash
   python bug-type-skills/bug-bounty-skill-creator/scripts/init_skill.py your-skill-name --path bug-type-skills --resources references
   ```

   This makes the folder, a starter `SKILL.md`, and `agents/openai.yaml`. You
   can also just copy a skill like `bug-type-skills/idor/` and change it.
   If you have the skills installed in Codex, you can ask it:
   *"Use $bug-bounty-skill-creator to add a skill for ..."*

4. **Write `SKILL.md`.** It starts with a short header (called frontmatter)
   that needs a `name` and a `description`. The name is lowercase with
   hyphens and matches the folder name. See the writing tips below for the
   rest.

5. **Write `references/advanced-methodology.md`.** This is where the deeper
   playbook goes. Start with a worked example of how this bug is usually
   found, then add the details.

6. **Fill in `agents/openai.yaml`.** Look at `bug-type-skills/idor/agents/openai.yaml`
   for an example. Keep `short_description` between 25 and 64 characters, and
   start `default_prompt` with `Use $your-skill-name to ...`.

7. **Add your skill to the table in [README.md](README.md).** Keep it in
   alphabetical order and describe it in one line.

8. **Check your work** (see below), then open a pull request.

## Writing tips

- **Write for Codex, and keep it short.** Codex already knows the basics of
  web security. Spend your words on what it wouldn't guess: where this bug
  usually hides, what one thing to change, what a real proof looks like, and
  what's a false alarm.
- **Get the description right.** Codex reads the `description` to decide
  whether to use your skill. Say what the skill covers and when to use it.
  Keep it under 1024 characters, and don't use `<` or `>`.
- **Start with a "Report-Derived Starting Point."** One short paragraph near
  the top of `SKILL.md`: the single test that most often finds this bug.
- **Show how to confirm a bug safely.** Use accounts and data you control,
  change one thing at a time, compare against a normal request, and stop at
  the smallest proof that shows the bug.
- **Use plain words.** Short sentences. Explain jargon the first time you use it.
- **Don't say the same thing twice.** If something's in `references/`, link to
  it from `SKILL.md` instead of copying it.

## Improving an existing skill

- Keep each pull request focused. One idea per PR is the easiest to review.
- In your PR, say what was wrong or missing and where the pattern comes from,
  for example: "seen in several public HackerOne reports about password reset."
  It's fine to link sources in the PR description, even though the skills
  themselves don't include report links.
- Don't rename a skill. People call skills by name, so renaming breaks things
  for them.

## If you change scripts

- Use only Python's built-in modules if you can. If you really need an extra
  package, say so in the skill and in your PR.
- Open files with `encoding="utf-8"` so the script works on Windows too.
- Run the existing tests, and add tests for what you changed:

  ```bash
  python -m unittest discover -s bug-type-skills/elite-bug-bounty-hunting/scripts
  ```

- The `bug-type-skills/bug-bounty-skill-creator/` folder is based on OpenAI's
  skill-creator and uses the Apache 2.0 license. If you change its files, keep
  its `license.txt` and add a line about your change to its `NOTICE` file.

## Checking your work

The validator checks the frontmatter, the name, and leftover `[TODO: ...]`
placeholders. It needs PyYAML, so install that once:

```bash
pip install pyyaml
```

Then run it on your skill:

```bash
python bug-type-skills/bug-bounty-skill-creator/scripts/quick_validate.py bug-type-skills/your-skill-name
```

It should print `Skill is valid!`. That only means the format is right, so
also:

- Read your skill once as if you've never seen it before. Does it make sense?
- Try it for real. Copy the folder into your Codex skills folder (usually
  `~/.codex/skills`), give Codex a realistic request, and see if it helps.

## Opening a pull request

In the PR description, say what you changed, why, and how you checked it.
Before you send it, make sure:

- [ ] It follows the ground rules at the top of this guide.
- [ ] The validator says `Skill is valid!`.
- [ ] New skills are added to the README table.
- [ ] There are no real secrets, personal data, or copied reports.
- [ ] Any scripts only touch local files, and the tests pass.

We'll review it as soon as we can and might suggest a few changes. That's
normal, so don't worry about it.

Thanks for helping make these skills better!
