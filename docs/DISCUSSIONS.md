# Discussions

**In short:**
[GitHub Discussions](https://github.com/tidynest/raven-nest-mcp/discussions)
is where these go:
- questions,
- ideas,
- tool proposals,
- field reports.

Issues are kept for ***bugs that someone can reproduce***.

## Contents

- [Where things go](#where-things-go)
- [Categories](#categories)
  - [Announcements](#announcements)
  - [Q&A](#qa)
  - [Ideas](#ideas)
  - [Tool proposals](#tool-proposals)
  - [Local models](#local-models)
  - [Show and tell](#show-and-tell)
  - [General](#general)
- [House rules](#house-rules)
- [What to expect](#what-to-expect)
- [Maintainer setup](#maintainer-setup)
  - [1. Enable Discussions](#1-enable-discussions)
  - [2. Set up the categories](#2-set-up-the-categories)
  - [3. Replace the welcome thread](#3-replace-the-welcome-thread)
  - [4. Check the links](#4-check-the-links)

## Where things go

| You have | Put it in |
|----------|-----------|
| a question about setup, config or an error message | Discussions, Q&A |
| a feature idea, or a preset you wish a tool exposed | Discussions, Ideas |
| a new tool you want wrapped | Discussions, Tool proposals |
| a report on how a local model behaved | Discussions, Local models |
| a workflow, prompt or lab write-up to share | Discussions, Show and tell |
| a bug you can reproduce | [Issues](https://github.com/tidynest/raven-nest-mcp/issues) |
| a way past a safety control | a private report, see [SECURITY.md](../SECURITY.md) |

## Categories

### Announcements

Releases and changes that break something.

***Only the maintainer posts here***. Anyone can reply.

### Q&A

Questions with an answer. Mark the reply that solved it, so the next person
finds it.

**Please include**
- how you run the server,
- which version,
- the error text.

### Ideas

Features, presets and changes to how something works.

***Describe the problem before the solution***. An idea that would loosen a
safety default should say who needs it and what stops it from being misused.

### Tool proposals

One thread per tool you would like wrapped.

The form asks the questions from
[CONTRIBUTING.md](../CONTRIBUTING.md#proposing-a-new-tool-wrapper), because a
wrapper is mostly ***a decision about what a model may ask for***.

### Local models

Reports on running the server with a model on your own hardware.

**Please include**
- which model,
- which client,
- what context size,
- what happened.

***Failures are as useful as successes***. Good reports get folded into
[LOCAL_AI_INTEGRATION.md](LOCAL_AI_INTEGRATION.md).

### Show and tell

Workflows, system prompts, client configs and write-ups from lab targets.

### General

Anything that fits nowhere else.

## House rules

1. **Authorised targets only**. Talk about systems you own, lab targets, or
   work you are permitted to do. Threads asking for help against someone
   else's system ***get closed***.
2. **No client data**. ***Do not paste*** scan output, findings, hostnames,
   addresses or credentials from a real engagement. Reproduce the problem
   against `scanme.nmap.org`, a lab target or `example.com`, or redact it
   properly. Remember that the audit log and findings contain targets.
3. **Vulnerabilities in Raven Nest go private**. If you can get past the
   allowlist, the scope, a gate or a cap, report it through
   [SECURITY.md](../SECURITY.md) and ***not in a thread***.
4. **Be decent to each other**. Disagree with the idea and leave the person
   alone.

## What to expect

One person maintains this project in their spare time, so ***answers can
take a few days***.

If you know the answer to someone else's question, please give it.

---

## Maintainer setup

These steps are ***for the repository owner*** and can be deleted from this
file once they are done.

### 1. Enable Discussions

Repository Settings, General, Features, tick Discussions. GitHub creates a
default set of categories and a welcome thread.

### 2. Set up the categories

In the Discussions tab, use the pencil next to Categories.

The slug is derived from the name, and each form in
`.github/DISCUSSION_TEMPLATE/` is matched to its category by slug, so ***the
names below need to be exact***.

| Category | Slug | Format | Action |
|----------|------|--------|--------|
| Announcements | `announcements` | Announcement | keep |
| Q&A | `q-a` | Question / Answer | keep |
| Ideas | `ideas` | Open-ended discussion | keep |
| Tool proposals | `tool-proposals` | Open-ended discussion | create |
| Local models | `local-models` | Open-ended discussion | create |
| Show and tell | `show-and-tell` | Open-ended discussion | keep |
| General | `general` | Open-ended discussion | keep |
| Polls | `polls` | Poll | delete, nothing here needs it |

**Suggested descriptions:**

- Announcements: Releases and breaking changes.
- Q&A: Setup, configuration and error messages.
- Ideas: Features, presets and behaviour changes.
- Tool proposals: Ask for a new tool to be wrapped.
- Local models: What worked and what did not with a model on your own hardware.
- Show and tell: Workflows, prompts and lab write-ups.
- General: Everything else.

Forms exist for `q-a`, `ideas`, `tool-proposals` and `local-models`. The
other categories use the plain editor.

### 3. Replace the welcome thread

Edit the thread GitHub created, or post a new one under Announcements and pin
it. A draft:

> **Welcome to Raven Nest Discussions**
>
> This is the place for questions, ideas and reports from people using Raven
> Nest. I maintain the project alone, so replies can take a few days. If you
> can answer someone else's question, please do.
>
> Where to post:
>
> - **Q&A** for setup and config questions
> - **Ideas** for features and presets
> - **Tool proposals** if you want a new tool wrapped
> - **Local models** to report how a model on your own hardware behaved
> - **Show and tell** for workflows and lab write-ups
>
> A few rules. Only discuss systems you are authorised to test. Never paste
> output from a real engagement. If you find a way around a safety control,
> report it privately through the Security tab and not here.
>
> If you run this with a local model, I would like to hear which one and how
> it went, good or bad. That is the part of the project where outside reports
> help most.

### 4. Check the links

These files all link to Discussions:
- the README,
- `CONTRIBUTING.md`,
- `.github/ISSUE_TEMPLATE/config.yml`.

Those links ***return 404 until step 1 is done***, so enable Discussions
before this branch reaches `main`.
