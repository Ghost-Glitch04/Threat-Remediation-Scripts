# Grow — Between-Phase Infrastructure Capture

## What this file is

This file documents `/reflect:grow`, the sub-command for **low-friction
capture of infrastructure-improvement ideas between phase boundaries**.
It covers:

1. **When to use `/reflect:grow`** vs. the full or light reflection
   workflows — the signals that distinguish a grow entry from a lesson
   entry.
2. **The standalone wishlist file** (`lessons_learned/meta/wishlist.md`)
   — format, location, and the invariant (INV-WISHLIST-01) that keeps
   it machine-parseable.
3. **First-pass sub-type classification** — how to apply the
   three-criterion test under the cognitive load of "in the middle of
   other work."
4. **Content standards** for wishlist entries that remain useful when
   the sweep step reads them weeks later.
5. **Integration with `/reflect:full`** — the sweep semantics that
   promote standalone entries into phase files during reflection.

Read this file:
- When authoring any entry via `/reflect:grow`
- When `/reflect:full`'s GATHER step sweeps the standalone wishlist
- When `/reflect:audit` surfaces orphaned or stale wishlist entries

This file works alongside `reference/meta_classification.md` (which
owns the three sub-types and the synchronous Step 6 semantics) and
`reference/templates.md` (which documents the standalone wishlist
file format under §"Standalone Wishlist File Format"). This file
goes deeper on the *discipline* of capturing mid-flow — how to get
useful entries into the system without breaking concentration on
the current task.

---

## Why `/reflect:grow` Exists — The Between-Phase Problem

V3.5's "What Would Help Me Grow" section lives inside phase files.
That placement works well at phase boundaries, when the author is
already in reflection mode. It works poorly for ideas that surface
mid-phase:

- **The phase file doesn't exist yet.** The idea came up during active
  work, before the phase's reflection.
- **Breaking flow is expensive.** Opening the phase file, writing a
  wishlist entry, and switching back to the work costs 5–10 minutes of
  attention recovery.
- **The idea evaporates.** Many infrastructure-improvement ideas are
  most salient *at the moment the friction is felt*. By the time full
  reflection runs at phase end, the specifics have faded.

The V3.5 pattern for this was "hope the author remembers at reflection
time." In practice, observed in Ghost's phase76–phase81, many
reflection-time wishlist entries are reconstructions of ideas that
originally occurred mid-phase. The reconstruction is lossy — specifics
fade; the visceral "this friction needs to be fixed" signal degrades.

`/reflect:grow` provides a minute-level capture path that preserves
the in-the-moment specificity without the ceremony of full reflection.

---

## When to Use `/reflect:grow`

### Signals that a grow entry is warranted

- **You just hit friction** that a script, helper, or convention would
  have prevented. Name the friction while it's fresh.
- **You noticed an environmental gap** — the linter doesn't catch X,
  the test harness doesn't support Y, the build script has no way to
  express Z.
- **You thought of an improvement to a methodology or approach** —
  "next time I should do X before Y" — that deserves to be captured
  but isn't a lesson from the current work.
- **You noticed the skill itself is missing something** — a rule you
  couldn't find, a check that should exist but doesn't.

### Signals that `/reflect:grow` is the WRONG sub-command

- **You just learned a specific lesson from the current work.** Use
  `/reflect:light` or wait for `/reflect:full`. Lessons go into the
  phase file narrative; grow entries are about the infrastructure
  around the work.
- **You have a CF item to open.** CF items track open debt from
  current work and belong in phase files, not the standalone wishlist.
- **You need to record a bug or design decision.** These are phase
  file content. Grow is for meta-observations — "the tooling could be
  better" — not for capturing what just happened.

The distinguishing test: **does the entry describe an improvement to
the scaffolding that would help *any future work*, or does it describe
something about *this specific work*?** Scaffolding → grow. This
work → phase file.

---

## The Standalone Wishlist File

### Location

`lessons_learned/meta/wishlist.md`

Created on first `/reflect:grow` invocation in a project. Included in
the scaffold by `/reflect:bootstrap` and `/reflect:retroactive` for
new projects and mature-repo initialization.

### Format (INV-WISHLIST-01)

One markdown table with exactly six columns, in this order:

```markdown
# Infrastructure Wishlist — Between-Phase Capture

| ID       | Sub-type       | Captured    | Description                                            | Step 6 outcome | Resolved         |
|----------|----------------|-------------|--------------------------------------------------------|----------------|------------------|
| TW-W-1   | meta-fix       | 2026-04-22  | `make check-css-vars` should also catch `rgb()` calls  |                |                  |
| TW-W-2   | meta-wish      | 2026-04-23  | `make new-tool` scaffolder would cut onboarding to 10m |                |                  |
| TW-W-3   | meta-question  | 2026-04-24  | Should wishlist.md itself be grep-checked by verify?   |                |                  |
```

**Column rules:**

| Column | Rule |
|---|---|
| `ID` | `TW-W-N` where `W` denotes "wishlist" (distinguishes standalone entries from phase-file `TW-N` entries). N is monotonic within this file. |
| `Sub-type` | One of: `meta-fix`, `meta-question`, `meta-wish`. Same vocabulary as phase-file wishlist entries (INV-WISHLIST-02). |
| `Captured` | ISO date `YYYY-MM-DD`. When the entry was captured via `/reflect:grow`. |
| `Description` | Under 100 characters. Frontload the concept. The entry's own body (if any) goes in a trailing details section — see below. |
| `Step 6 outcome` | Populated by `/reflect:full` sweep only. Values: `APPLIED`, `DECLINED`, `DEFERRED`, or empty (not yet swept). |
| `Resolved` | Populated by `/reflect:full` sweep only. `{phase_id}` when the entry is promoted and closed; empty while pending. |

### Extended-body section (optional)

For entries that need more than a 100-character description, use a
trailing details block referenced by ID:

```markdown
## Details

### TW-W-2 — `make new-tool` scaffolder

Onboarding a new tool currently takes 40+ minutes across 8 locations
(CLAUDE.md, taxonomy.py, test fixtures, docs, etc.). A scaffolder
would take a tool name and generate the stub entries in each location.

The tricky part is the test fixture — it has different shapes for
network vs. local tools. A scaffolder would need a --kind flag.
```

The `### TW-W-N —` heading is the lookup anchor. Grep for `TW-W-N`
against `wishlist.md` finds both the table row and (if present) the
details section.

### Append-only semantics

Entries are added to the bottom of the table during capture. **Never
rewrite existing rows.** The only modifications allowed mid-life are:

- **`/reflect:full` sweep** writes to the `Step 6 outcome` and
  `Resolved` columns when an entry is promoted. No other columns
  change.
- **`/reflect:grow` reclassification** — if the author later decides
  an entry's sub-type was wrong, change the `Sub-type` cell in place.
  Record the reclassification in skill_dev_log.md if the pattern
  recurs (suggests classification discipline needs adjustment).

Promoted entries are marked `Resolved`, not deleted. This preserves
the audit trail for `/reflect:audit` to compute action rates over
time.

---

## The `/reflect:grow` Workflow

### Step 1 — State the friction or opportunity

The author describes what prompted the capture in one or two
sentences. No formatting discipline yet; the goal is to get the
thought into the system before it fades.

Example prompts (any of these is a valid start):
- "The test harness can't express per-tool environment setup; I keep
  having to edit conftest.py."
- "There's no single command to regenerate the taxonomy cache after
  editing service_taxonomy.yaml."
- "I noticed wpscan.md uses a different source-pointer format than
  every other AI file. That should probably be normalized."

### Step 2 — First-pass sub-type classification

Apply the three-criterion test (from `meta_classification.md` §"The
Three-Criterion Test"):

1. **Location known** — is the exact file or target specified?
2. **Content known** — is the replacement text specifiable without
   design work?
3. **No plausible alternative** — would two reasonable implementers
   produce substantially the same fix?

All three pass → `meta-fix` (tentative — `/reflect:full` adjudicates).
Any one fails → `meta-question`.
Adding *new capability* rather than fixing drift → `meta-wish`.

**Under cognitive load, default conservatively.** If you're mid-task
and can't fully evaluate the criteria, choose `meta-question`. The
sweep at `/reflect:full` will reclassify with full context. The cost
of mis-calling `meta-question` is one reflection cycle of delay; the
cost of mis-calling `meta-fix` is a synchronous edit that shouldn't
have happened.

### Step 3 — Write the description

Under 100 characters. Frontload the concept. Use imperative or
noun-phrase form — not narrative.

| Pattern | Example |
|---|---|
| Noun phrase | `make new-tool scaffolder to cut onboarding to 10 minutes` |
| Imperative | `Add --kind flag to test fixture for network vs. local tools` |
| Diagnosis | `wpscan.md Source-pointer format diverges from 18 other AI files` |

Avoid:
- **Narrative descriptions** — `When I was editing conftest.py today I
  realized...` — prose, not a scannable entry.
- **Vague wishes** — `Testing should be better` — not actionable at
  any level.
- **Self-reference without object** — `Fix the thing we discussed` —
  no grep target.

### Step 4 — Append to the standalone wishlist

Write one row to the table. If the entry needs more context than 100
characters, add an extended-body section keyed by ID.

### Step 5 — Return to work

No sweep runs. No Step 6 fires. No edits to other files. The entry
waits in `wishlist.md` for the next `/reflect:full` invocation.

---

## Content Standards

### What makes a wishlist entry useful at sweep time

A `/reflect:full` sweep runs days or weeks after capture. The author
reading the entry at sweep time may have lost the specific context.
Good entries survive context fade. Three tests:

**Test 1: Recoverable context.** Does the description name enough
specifics (file, function, flag, error class) that the author can
mentally reconstruct the friction? A description of "the linter
problem" fails; "ESLint doesn't catch unused async/await pairs in
callback-nested code" passes.

**Test 2: Scoped ambition.** Does the entry describe a bounded
improvement, or is it aspirational? `meta-fix` and `meta-wish`
entries should have a scope the author can imagine completing.
`meta-question` entries can be more open-ended because the design
thought *is* the scope.

**Test 3: Survives tool-stack changes.** If the project adopts a new
linter, tester, or build system next month, does the entry still make
sense? Entries tied to specific tool quirks should name the tool;
entries about methodology should be tool-neutral.

### Anti-patterns

**Anti-pattern 1: Debugging narrative.**
```
TW-W-7 | meta-question | 2026-04-20 | The parser was being weird today and I had to restart the test runner
```
Not an improvement proposal — an incident report. Belongs in a phase
file (or nowhere) if there's no systemic lesson.

**Anti-pattern 2: Feature aspiration without specifics.**
```
TW-W-8 | meta-wish | 2026-04-20 | Better error handling across the board
```
No target, no scope, no fix. A future sweep has nothing to act on.
Rewrite as a specific proposal or drop.

**Anti-pattern 3: Duplicate of existing CF or phase-file entry.**
```
TW-W-9 | meta-fix | 2026-04-20 | Fix the taxonomy normalization issue from phase82
```
Phase-specific problems go in phase files. The standalone wishlist is
for scaffolding improvements that aren't tied to a specific work unit.

**Anti-pattern 4: Classification gaming.**
```
TW-W-10 | meta-fix | 2026-04-20 | Completely rewrite the rules engine
```
Classified `meta-fix` to get synchronous Step 6 treatment, but fails
the three-criterion test — scope is unbounded, content is not
specifiable, multiple reasonable designs exist. The sweep would
reclassify to `meta-question` or `meta-wish`. Classify honestly at
capture time.

---

## Integration with `/reflect:full` — The Sweep

### When the sweep runs

SKILL.md §4a Step 1 GATHER, after evidence-block execution and before
reading the most recent phase file. The sweep is a read of
`wishlist.md` with in-context review:

```
For each row in wishlist.md where Resolved is empty:
  1. Reclassify with full-context judgment
     (apply three-criterion test with the full reflection's evidence)
  2. Decide promotion path:
     a. Still meta-fix         → promote to phase file Grow section,
                                 route through Step 6
     b. Still meta-question    → promote to phase file Grow section
                                 as-is, no Step 6
     c. Still meta-wish        → promote to phase file Grow section
                                 as-is, no Step 6
     d. Reclassified            → update wishlist.md Sub-type cell,
                                 then promote with new classification
     e. No longer relevant     → mark Resolved with reason
                                 "superseded / obsolete", don't promote
  3. Mark Resolved with {phase_id}
```

### The promoted phase-file entry

When an entry is promoted, it's written into the current phase file's
"What Would Help Me Grow" section with:
- A new ID in the phase file's local numbering (`TW-{N}`, not
  `TW-W-N`)
- A back-pointer to the original: `*(originally TW-W-N in wishlist.md,
  captured {date})*`
- The sub-type (possibly reclassified)
- Either the original description or a refined version

If Step 6 runs on a promoted `meta-fix` entry, the standard Step 6
outcome annotation (`**Step 6 outcome:**`) appears on the phase file
entry. The standalone wishlist's `Step 6 outcome` cell mirrors the
phase file's outcome.

### Uncommitted-changes deferral

If `wishlist.md` has uncommitted changes at the time of sweep
(e.g., captured entries from a grow invocation that hasn't been
committed yet), the sweep defers. Promotion of in-flight entries
risks promoting an entry the author was about to revise.

The fallback is to ask the author: "wishlist.md has uncommitted
entries — commit, discard, or defer sweep?" Defer is the safe
default; the entries wait for the next `/reflect:full`.

---

## Integration with `/reflect:audit` — Visibility

`/reflect:audit` surfaces four feedback-loop signals (see
`reference/audit.md`), three of which touch the standalone wishlist:

**Orphaned wishlist entries.** Rows with empty `Step 6 outcome` and
empty `Resolved` older than 2 full reflections. These are grow
entries that accumulated but never got swept — suggests either the
sweep step is being skipped or grow is being used as a parking lot
rather than an active capture tool.

**Stale `meta-fix` entries.** Rows classified `meta-fix` with
`Step 6 outcome: DEFERRED` or empty after 3+ sweep opportunities.
These are fixes the synchronous loop keeps declining to apply —
suggests the classification is wrong (should have been
`meta-question`) or the fix is contested.

**Wishlist growth rate.** If `wishlist.md` accumulates entries faster
than `/reflect:full` sweeps them, the capture side is outpacing the
adjudication side — suggests more frequent full reflections or a
dedicated skill-development reflection.

---

## When This Workflow Is Wrong

Three scenarios where `/reflect:grow` is not the right tool:

**1. Lightweight capture of an actual lesson from current work.**
`/reflect:light` exists for this. Grow is for scaffolding ideas;
light is for lessons from the work itself. If you're describing what
you *just learned*, use light.

**2. Crisis-mode work where any ceremony is friction.** If the current
task is fire-fighting, *any* capture is optional. Come back to grow
once the fire is out. The wishlist doesn't reward speed-of-capture
over preservation of current work.

**3. Meta-observations that belong in `skill_dev_log.md`.** If the
observation is about the lessons-learned skill's own design or about
a pattern across multiple reflections, it's probably a
skill-development note, not a wishlist entry. Write it to
skill_dev_log.md directly. The wishlist is for project-level
infrastructure; skill_dev_log is for skill-level evolution.

---

## Change Control

Changes to `/reflect:grow` or the standalone wishlist file:

- **Adjusting the capture prompt or description-length guideline:**
  No version bump. Record as drift-formalization in skill_dev_log.md
  if the change is substantive.
- **Adding a seventh column to `wishlist.md`:** Skill version bump
  (INV-WISHLIST-01 is a column-count contract). Existing rows need
  to be migrated.
- **Changing the sub-type vocabulary:** Skill version bump (shared
  invariant with `meta_classification.md` — INV-WISHLIST-02 mirrors
  the phase-file wishlist sub-type vocabulary).
- **Changing the sweep semantics** (when it runs, what it promotes):
  Skill version bump. The sweep is part of the `/reflect:full`
  workflow contract.
- **Adjusting the orphan and stale thresholds in `/reflect:audit`:**
  No version bump; these are heuristics. Record in skill_dev_log.md.

### Signals the workflow is working

Track across reflections to validate the hypothesis that mid-flow
capture preserves specificity better than reflection-time
reconstruction:

- **Capture-to-sweep latency:** Median days between a wishlist entry's
  `Captured` date and its `Resolved` date. Baseline from V3.5
  experience (reflection-time wishlist entries only): 0–2 phases
  (days to weeks). V3.6 target: same order of magnitude, but
  measuring from *capture* date rather than *phase* date — expecting
  the specificity-at-capture hypothesis to show up in the action
  rate, not the latency.
- **Sweep-time reclassification rate:** % of entries whose
  `meta-fix / meta-question / meta-wish` classification changes
  during `/reflect:full` sweep. Expected: 10–20%. Much higher
  suggests first-pass classification discipline is weak; much lower
  suggests the sweep isn't doing real adjudication.
- **Grow vs. reflection-time capture ratio:** % of wishlist entries
  that originate from `/reflect:grow` vs. originating in phase files
  directly. A healthy ratio depends on how much mid-phase friction
  the author notices — there's no single right value, but tracking
  the trend reveals whether grow is actually being used or whether
  the between-phase capture hypothesis is unsupported.

These signals feed future `/reflect:audit` outputs and eventual
skill-development reflections.
