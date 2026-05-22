# Templates — Exact Formats for Lessons Learned

This file contains every format SKILL.md refers to. Read it before writing any
lesson entries. The formats here are drawn from observed practice in the real
`lessons_learned/` directory — not from an idealized schema. If a future reflection
uses a format that isn't documented here, update this file first, then write the entry.

---

## Phase File Structure

Each phase file is one markdown document with this skeleton:

```markdown
# Phase {N} — {Short Title}

**Tags:** tag1, tag2, tag3

---

## Overview

2–5 sentences framing the scope of this phase and the headline outcome.

---

## Section 1 — {Topic} (optional grouping)

### 1. {Entry Title}

Narrative body: what happened, what was learned, what the code does now.

**Lesson:** One-line takeaway that can stand alone.

### 2. {Entry Title}
...

### 3. {Entry Title}
...

---

## Applied Lessons
(See "Applied Lessons Table Format" below)

## What Went Well
3–5 bullets. Approaches that worked or decisions validated.

## Bugs and Pitfalls
Numbered entries for each non-trivial technical bug encountered. Root cause and fix.

## What Went Badly (optional)
Judgment calls that wasted effort, ignored warnings, premature optimization,
stale assumptions, near-misses caught by a later step. Distinct from Bugs —
bugs are specific technical failures; badly covers decisions you'd make
differently with hindsight.

## Design Decisions
Entries for non-obvious architectural or structural choices with tradeoffs.

## Carry-Forward Items
(See "Carry-Forward Items Table Format" below)

## What Would Help Me Grow — Tooling Wishlist (optional)
Meta-level observations about the skill, tooling, or environment itself.
Entries here may surface a gap in the lessons-learned skill itself — those
entries are the seed for the next skill-authorship reflection.

## Metrics
(See "Metrics Table Format" below)
```

**Key conventions observed in the real repo:**
- Entry headings are `### N. {Title}` — single-integer numbering, monotonic
  within the phase file. This is the dominant format (30 of 31 phase files).
- Sections (`## Section N — Topic`) are an **optional grouping layer** used
  only when a phase file has many entries that benefit from being clustered.
  When sections are used, entry headings may also be two-level
  (`### N.N Title`, section.entry) — observed in `phase22_testing.md` only.
- `**Lesson:**` bold line at the end of each entry is the grep anchor used by
  some INDEX entries — keep it consistent.
- The "Overview" section is always present, always short.
- Optional sections (Applied Lessons, Bugs, etc.) can be omitted when they
  have no entries; phase files do not pad empty sections.

---

## Phase File Variants

A phase file declares its variant on its own line in the header
block, typically right after the H1 title:

```markdown
# Phase 76 — Modal Fix Session

**Format:** canonical
**Tags:** ui, e2e, testing
```

The `**Format:**` line is invariant INV-PHASE-08. The variant name
must be one of the three documented variants below, or a
proposed-variant name flagged by the Drift Intake Protocol (see
`reference/drift_intake.md`).

V3.5 introduced three documented variants. They differ only in
*presentation* — retrieval invariants (entry numbering, anchor
discipline, table column shapes, source pointer formats) apply
identically to all three.

### Variant 1: `canonical`

**Signal:** Default. Single coherent unit of work — a feature, a
refactor, a testing pass, an incident response. Has a definable
scope and outcome.

**Required sections:**
- Overview
- One of: Applied Lessons, OR Applied Lessons + Missed split

**Optional sections:**
- What Went Well
- Bugs and Pitfalls
- What Went Badly
- Design Decisions
- Carry-Forward Items
- What Would Help Me Grow — Tooling Wishlist
- Metrics

**Validation:** All standard verify.md checks apply (Checks 1, 2, 3,
14). Anchor discipline (INV-PHASE-02) applies to all entries in
Bugs/Design Decisions sections.

**Example:** Most phase files in any project will be canonical. See
§"Worked Example" below for a worked canonical phase file.

### Variant 2: `meta-reflection`

**Signal:** Reviewing multiple phases at once for arc-level patterns.
Synthesis across constituent phases rather than a single unit of
work. Used for "what did we learn across phases 76-81?"

**Required sections:**
- Overview
- Summary Judgment (prose synthesis of cross-phase patterns)
- Phase Inventory (list of constituent phases with brief scope notes)

**Optional sections:**
- Cross-phase Patterns (insights spanning multiple phases — typically
  type `insight` in INDEX.md)
- Cross-phase Bugs (bug *classes* that recurred — distinct from
  phase-specific bug entries)
- Cross-phase Decisions (architectural decisions emerging from the arc)
- What Would Help Me Grow

**Sections that DO NOT apply (live in constituent phases instead):**
- Per-phase Applied Lessons / Missed tables — each constituent phase
  has its own; the meta-reflection points to them, doesn't duplicate
- Per-phase Carry-Forward Items — same
- Per-phase Metrics — same

**Validation:** Anchor discipline applies only to *indexed* entries
(those that will appear in INDEX.md as a rule, bug, pattern, or
insight). The Summary Judgment prose section is not an indexed
entry — it's narrative synthesis — and does not require a
`**Lesson:**` anchor. See `evidence.md` §"When This Discipline Is
Wrong" §1.

**Example:** Phase files like `phase76-81_arc.md` (covering an arc
of phases) typically use this variant.

### Variant 3: `case-study`

**Signal:** Teaching artifact for future sessions doing similar work.
The phase file's audience is future Claude sessions or future humans
working on similar problems. The file is organized for *pedagogy*,
not for retrieval.

**Required sections:**
- Overview
- Descriptive teaching sections (free-form headings, not canonical
  section names)

**Optional sections:**
- The Setup (context the reader needs)
- The Problem (what specifically was being faced)
- The Approach (what was tried)
- The Outcome (what worked, what didn't)
- Generalized Lessons (any actionable rules — these MUST follow
  anchor discipline if indexed)
- Carry-Forward Items
- What Would Help Me Grow

**Sections that may be omitted entirely:**
- Applied Lessons / Missed tables — case studies focus on teaching,
  not feedback-loop tracking; include them only if relevant
- Bugs and Pitfalls — the case study itself often *is* the "bug story"
- Metrics — often not the point of the case study

**Validation:** Anchor discipline applies only to indexed actionable
entries (typically in "Generalized Lessons" if present). Teaching
prose sections are not indexed and do not require anchors. See
`evidence.md` §"When This Discipline Is Wrong" §2.

**Example:** Phase files documenting a complex technique as a case
study rather than a chronological reflection.

### Drift Intake — When None of the Three Fit

If a reflection doesn't fit any documented variant, the author MUST
NOT silently invent a fourth. Instead:

1. Run the Drift Intake Protocol (`reference/drift_intake.md`) to
   propose a new variant name with rationale
2. Use the proposed name in the `**Format:**` declaration
3. Document the new variant here in templates.md if it recurs across
   3+ reflections (variant graduation criterion)

Until graduation, Check 16 (variant conformance) reports the proposed
variant as drift but does not fail — drift intake is the formal route
for variant evolution.

### Variant invariants (what stays constant across all variants)

Regardless of variant, these invariants apply:

| Invariant | Statement |
|---|---|
| INV-PHASE-01 | Indexed entries use `### N. Title` numbering |
| INV-PHASE-02 | Bugs/DD entries have a `**Lesson:**` anchor with citation |
| INV-PHASE-03 | Applied Lessons table columns are exact when present |
| INV-PHASE-04 | Applied Lessons source-cell format is one of four documented forms |
| INV-PHASE-05 | Outcome vocabulary is the 9-value set |
| INV-PHASE-06 | Missed table columns are exact when present |
| INV-PHASE-07 | CF-N IDs are stable across phases |
| INV-PHASE-08 | `**Format:**` declaration line is present |
| INV-PHASE-09 | Superseded markers are bidirectional |

These are the contract; variants govern what's *optional* around
the contract, not what changes within it.

---

## Phase File Entry Format

Individual entries inside a section follow this shape:

```markdown
### 5. Wpscan detection-mode passive saves ~55s on every probe

Wpscan's default `mixed` mode runs `wp_version/unique_fingerprinting.rb`,
which probes 571 JS/CSS files to compute version checksums. This takes
~57s before the actual password-attack work begins. In `passive` mode,
wpscan reads the HTML once (~2s) and moves on.

| Mode | Time | Use case |
|------|------|----------|
| mixed (default) | ~62s | Never in 60s probes |
| passive | ~9s | Always in integration probes |

**Lesson:** Add `--detection-mode passive` to every wpscan probe in a
≤60s timeout.
```

Every entry has:
1. `### N. Title` — single-integer numbering, title frontloaded with the
   concept (not a verb). Two-level `### N.N Title` is acceptable only when
   the phase file uses `## Section N — Topic` grouping (rare — one file).
2. Narrative body — short paragraphs, optional tables, optional code blocks
3. `**Lesson:**` — a single-sentence takeaway that can stand alone when
   grep-hit without the narrative body

---

## INDEX.md Row Format

INDEX.md is the grep-optimized discovery layer. Every row is one line,
pipe-delimited, with exactly four columns:

```
| tags | description | source | type |
```

**Example rows from the real repo:**
```
| wpscan, testing | Passive detection-mode saves ~55s on every probe; default mode fingerprints 571 files before attacking | phase22_testing:5 | rule |
| metasploit, windows | winrm_cmd runs commands over WinRM without dropping a payload — zero AV surface | phase17_msf_sql01:3 | pattern |
| docker, alembic | Alembic upgrade must run inside Docker container; postgres hostname only resolves in Docker network | phase3f_osint_stage | rule |
```

**Column rules:**

| Column | Rule |
|---|---|
| `tags` | Lowercase, comma-separated, primary tag first, no spaces inside a tag (use `-` for multi-word). Primary tags come from the project's tag vocabulary — see INDEX.md top section. |
| `description` | Under 120 characters. Frontload the key concept. Grep hits must be useful without loading the source. |
| `source` | `{phase_id}:{N}` where `{N}` is the integer entry number in the phase file (e.g., `phase17_msf_sql01:3`). The `.md` suffix is omitted. If the lesson spans a whole phase file with no specific entry, use just `{phase_id}`. Range (`phase7_sbom_debugging:1-4`) and multi-entry (`phase6_filesystem_tools:1,5,6`) forms are accepted. |
| `type` | One of: `rule`, `bug`, `pattern`, `insight`. See Type Vocabulary below. |

**Type vocabulary (four types, not three):**

| Type | Definition | Example |
|------|------------|---------|
| `rule` | Prescriptive: "always X" or "never Y". Violating causes predictable failure. | "Validate UUID before any DB query" |
| `bug` | Specific failure encountered and fixed. Record failure mode + root cause. | "Batch insert silently drops rows over 1000" |
| `pattern` | Reusable approach that worked. Not prescriptive — alternatives exist. | "Fixture-driven parser testing" |
| `insight` | Meta-observation about process, methodology, or architecture. Not code-level. | "Two-round Build+Validate → Adversarial Review predicted which bugs each round should catch" |

Default to `rule` when uncertain. `insight` is reserved for process/methodology
observations; don't dilute it by tagging every general observation as one.

**Source-pointer format for AI files is different — see AI File Rule Format.**
INDEX rows and AI file rules each have their own pointer shape, don't mix them.

---

## AI File Rule Format

AI subject files are the structured-recall layer. A cold-start session reads
one or two files and gets working rules without narrative overhead.

```markdown
### Short imperative title
<!-- tags: primary, secondary -->

**When:** The specific context where this rule applies. One line.
**Not when:** (optional) Contexts where the rule does NOT apply, one line.
**Rule:** The rule statement. One or two sentences. Prescriptive voice.

```bash
# Code example showing the correct and incorrect pattern side by side
# WRONG:
gcc test.c   # error: limits.h not found on slim Ubuntu

# RIGHT:
apt-get install -y gcc libc6-dev   # both required together
```

**Why:** (optional) One-sentence reason, typically the underlying mechanism.
Include this when the rule sounds arbitrary without the explanation.

**Companions:** (optional) file.md → "Rule Title", file.md → "Rule Title"

*Source: phase18_tool_testing:5*

---
```

**Heading format (canonical):** `### Short imperative title` — plain H3
with the rule stated as an imperative. This is the format used by 17 of
18 AI files in the real repo. Titles do not include a `Rule N:` prefix;
rules are looked up by grep-matching the title text or the optional
`<!-- tags: -->` comment that follows.

**Heading format (legacy — wpscan.md only):** `### Rule N: Short title` —
the `Rule N:` prefix is used in `lessons_learned/ai/wpscan.md` only
(12 rules). Rules are numbered, restart at 1, and increase monotonically.
This format is valid historical drift; new AI files should use the plain
canonical format unless they have a strong reason to number their rules.

**Source format inside AI files:** `*Source: {phase_id}:{N}*` — italicized,
`.md` suffix omitted, no `§` anchor. The `N` after the colon is
**polymorphic**: it can be an **entry number** (matches `### N. Title` in
the phase file) OR a **line number** (when the phase file has H2 sections
or no numbered entries, or when deeper granularity is needed). Both
interpretations are observed and both are valid.

| Form | Example | N means |
|------|---------|---------|
| Single entry | `*Source: phase16_metasploit_target:5*` | entry or line |
| Phase ID only (no :N) | `*Source: phase19_wrapper_gaps*` | whole file |
| Multi-value in one phase | `*Source: phase9_vulnerable_target:1,2*` | entries or lines |
| Range | `*Source: phase7_sbom_debugging:1-4, 6-7*` | entry range |
| Multi-phase | `*Source: phase10_nuclei:4, phase11_nuclei:2*` | entries |
| Alpha entry ID | `*Source: phase18_tool_testing:A1*` | labeled entry |
| Parenthetical context | `*Source: phase6_filesystem_tools:4 (StringsWrapper bug)*` | entry + note |
| Cross-phase annotation | `*Source: phase5_terminal_notes:adversarial (corrects phase3e_operational:350)*` | named + corrected line |
| Section-anchor (wpscan.md only) | `*Source: phase22_testing.md §2.1*` | section §entry |

**Prefer plain `phase_id:N`** for new rules. When in doubt about whether
to use an entry number or a line number, use the entry number — it's more
stable across phase file edits. Avoid inventing new variations — Check 13
(format drift) flags any AI file whose pointer forms fall outside this table.

**wpscan.md section-anchor legacy:** `lessons_learned/ai/wpscan.md` uses
`*Source: {phase_file}.md §{section}*` in all 12 rules. This is the only
file using the `.md §` variant. New reflections should use canonical
`phase_id:N`; wpscan.md is either reconciled in a future phase or left as
historical drift.

**When/Rule discipline — isolation read:** After writing a rule, re-read only
the **When**, **Not when**, and **Rule** lines in isolation from the surrounding
narrative. If those three lines don't carry the rule without the code block or
Why, a future session that grep-hits only the rule heading will get nothing
actionable. Rewrite until the rule is self-contained in its When/Rule pair.

**Not when:** Add a **Not when** boundary when the rule's keywords overlap a
context where the rule actively doesn't apply. Example: a rule about "probe
timing in wpscan integration tests" should have `**Not when:** Running wpscan
manually outside an integration harness — there is no 60s kill deadline.`
Sparse use is fine; 19 instances across 7 files in the real repo is not an
under-use — it's the right density.

**Companions:** Add `**Companions:** file.md → "Rule Title"` when another rule
in a different file addresses a related facet that this rule's effectiveness
depends on. Links must be mutual — if A lists B as a companion, B must list A.
The verify.md Check 6b confirms mutuality. Keep the list to 1–3 entries;
larger clusters belong in a concern map (deferred — see §"Deferred Features").

---

## Applied Lessons Table Format

The Applied Lessons table is the feedback loop between **lookup** and **capture**.
It records which prior rules the session consulted during work and whether
they helped.

**Format:**

```markdown
## Applied Lessons

| Rule (source → heading) | Outcome | Note |
|-------------------------|---------|------|
| wpscan.md → "Rule 1: detection-mode passive" | applied | Saved ~55s per probe on 14 probes |
| process.md → "Lookup-before-work" | REGRESSED | Knew the rule, still skipped lookup on the bash script trap |
| feedback_shell_testing_traps (memory) | REGRESSED | Memory caught it after the test run, not before |
| testing.md → "Mock fidelity" | in place | No mocks touched this phase |
| docker.md → "CLI tool vs language binding" | applied proactively | Added libc6-dev alongside gcc on sight |
| NEW (this phase) | discovered | wpscan xmlrpc body-credential-extraction vector |
```

**Columns:**

| Column | Rule |
|---|---|
| `Rule (source → heading)` | Either `{ai_file}.md → "{Rule Title}"` or `{memory_file} (memory)` or `NEW (this phase)` for rules discovered during this phase. |
| `Outcome` | One of the vocabulary values below. |
| `Note` | One-line context. What specifically about this phase made the rule apply, fail, or get skipped. |

**Outcome vocabulary — nine values:**

| Outcome | Meaning |
|---|---|
| `applied` | The rule was looked up, consulted, and used to make a decision. |
| `applied proactively` | The rule was recalled from prior work without a lookup — automatic application. |
| `in place` | The rule was already satisfied by existing code; no change needed this phase. |
| `N/A` | The rule was consulted but didn't apply to this phase's context. |
| `missed` | The rule existed in INDEX/AI files but was **not consulted** during work. Discovered in hindsight during reflection. |
| `REGRESSED` | The rule was **known** (in memory, prior Applied table, or personal recall) and **still violated**. Distinct from missed — missed is "didn't know to look", REGRESSED is "knew, didn't consult, failed". |
| `contradicted` | The rule was followed and caused a failure. The rule itself is wrong or needs a Not-when boundary. |
| `revised` | The rule applied in spirit, but this phase discovered a new boundary condition. Feeds a Not-when addition. |
| `discovered` | A new rule created this phase, not looked up from prior work. Lets the Applied table double as a first-pass catalog of new rules. |

**`REGRESSED` is the most important outcome.** It directly diagnoses
lookup-protocol failure — the exact feedback loop this skill exists to
strengthen. If a phase's Applied table has any `REGRESSED` rows, the next
phase's `Missed` scan should include those rules and the cause of the lookup
miss should be named. Repeated `REGRESSED` on the same rule is a signal to
escalate the rule from AI file to memory file, or vice versa, or to adjust
the rule's trigger keywords.

**Every Applied row with outcome `missed` or `REGRESSED` must also appear in a
Missed entry if a split Applied/Missed table is in use** (see below).

---

## Missed Table (Applied Lessons split)

A phase can optionally split the Applied Lessons section into two tables:

```markdown
## Applied Lessons

| Rule (source → heading) | Outcome | Note |
|-------------------------|---------|------|
| (only rows with outcomes: applied, applied proactively, in place, N/A, revised, discovered)

## Missed

| Rule (source → heading) | Why missed | Consequence |
|-------------------------|------------|-------------|
| process.md → "Lookup-before-work" | Skipped the lookup step on fresh bash script | Wrote `[[ ]] && cmd` under set -e, bash script crashed at runtime |
| feedback_shell_testing_traps (memory) | Memory not reviewed before writing the test script | Silent failure in timeout wrapper, had to debug from scratch |
```

**Why split?** Applied is easy to bias-fill — you remember what you used.
Missed requires a separate grep pass against INDEX.md (targeted at the tags
the phase touched) which is where real growth happens. The split forces the
grep pass. Small phases can keep the single combined table; large phases or
phases where lookup discipline is being actively measured should split.

**Discovery procedure for Missed:**
1. Identify the tags that describe this phase's work area (usually 2–4 tags).
2. `grep -i "{tag}" lessons_learned/INDEX.md` for each tag.
3. For each hit, ask: was this rule consulted during work? If no, is it a
   genuine miss or is its Not-when satisfied?
4. Genuine misses go in the Missed table with a "Why missed" column.

---

## Carry-Forward Items Table Format

Open debt that a phase creates but does not resolve. Must be tracked in a
table so each item has a stable ID across phases.

```markdown
## Carry-Forward Items

| ID | Item | Priority |
|----|------|----------|
| CF-1 | Re-verify phase-9's "SUID bits stripped by Docker" claim — didn't reproduce in privesc ecology. | Low |
| CF-2 | Document the SNMP port quirk (`11161` works, `1161` doesn't) in an inline comment. | Medium |
| CF-3 | Add a `make test-targets-all` CI smoke job — currently the full 87-probe run is manual. | Medium |
```

**Conventions:**
- `CF-N` IDs are stable across phases. A CF-N created in phase5 remains CF-N
  in phase6 unless resolved.
- When a CF item is resolved in a later phase, the resolving phase's
  Carry-Forward section includes: `| CF-N | RESOLVED in phase{N}_{name}: brief note | — |`.
- Priority vocabulary: `Low`, `Medium`, `High`, `Critical`.
- CF items are **debt with a due date** — unresolved items roll forward
  into the next phase's Carry-Forward table automatically. Don't drop them.

**CF-N is a table column value, not a line prefix.** The V3_3 skill documented
`CF-N: description` as a prefix format — that format is not in use anywhere
in the real repo. Tables are the observed format.

---

## Metrics Table Format

Records quantitative measurements of phase output. Optional but recommended.

```markdown
## Metrics

| Metric | Value |
|--------|-------|
| Probes added | 14 (101 total, up from 87) |
| New AI rules | 12 (wpscan.md: 12) |
| Existing rules applied | 8 |
| Rules REGRESSED | 2 |
| CF items opened | 3 |
| CF items resolved | 1 (CF-6 from phase21) |
| Session count | 4 |
| Phase duration | 3 days |
```

Metrics that are hard to measure are fine to omit. Three categories that
are *always* valuable to capture if available:
1. **New knowledge added** (rule count, CF count)
2. **Prior knowledge exercised** (applied count, REGRESSED count)
3. **Work output** (probe count, test count, feature count)

The REGRESSED count is the most important single metric — it's the direct
measure of whether the lookup protocol is working. A phase with 3+ REGRESSED
rows is a signal that the next phase needs a stricter lookup discipline.

---

## Superseded Rules Format

When a rule is replaced or corrected (not merely refined), both sides must
be marked so a grep hit on the old rule redirects to the new one.

**In the superseded AI rule:**

```markdown
### Rule 7: Old rule title

**Superseded by:** docker.md → "Rule 18: New rule title"
**Supersession reason:** corrected — the original rule was wrong about SUID
bit preservation in Docker layers. The phase-21 privesc ecology proved they
do persist; phase-9's original observation was specific to the older
supervisord-based image.

(original body retained below for context)
```

**In INDEX.md:**

```
| docker | [SUPERSEDED] Docker build layers strip SUID bits — see Rule 18 | phase9_vulnerable_target | rule |
```

**Supersession reasons — controlled vocabulary:**

| Reason | Meaning |
|---|---|
| `corrected` | The old rule was factually wrong. New rule replaces it entirely. |
| `refined` | The old rule was directionally correct but the new rule adds a boundary condition or generalizes the statement. |
| `narrowed` | The old rule was too broad. New rule applies only in a narrower context. |
| `split` | The old rule covered two distinct cases. New rules handle each case separately. |

**Forward pointers must be mutual.** If Rule 7 is superseded by Rule 18, Rule
18 should list Rule 7 in a `**Supersedes:** docker.md → "Rule 7: old title"`
line. Verify.md Check 11 confirms both sides.

**Superseded rules are excluded from `_overview.md` rule counts** — they no
longer provide actionable recall.

---

## Standalone Wishlist File Format

The standalone wishlist file (`lessons_learned/meta/wishlist.md`)
captures infrastructure-improvement ideas between phase boundaries
via the `/reflect:grow` sub-command. The file format is invariant
INV-WISHLIST-01.

### Location and lifecycle

| Aspect | Specification |
|---|---|
| Path | `lessons_learned/meta/wishlist.md` |
| Created | On first `/reflect:grow` invocation in a project |
| Initialized by | `/reflect:bootstrap` and `/reflect:retroactive` for new projects |
| Read by | `/reflect:full` (sweep step), `/reflect:audit` (orphan detection) |
| Written by | `/reflect:grow` (append), `/reflect:full` (sweep updates) |

### Structure

The file has one main table with exactly six columns in this order:

```markdown
# Infrastructure Wishlist — Between-Phase Capture

| ID       | Sub-type       | Captured    | Description                                            | Step 6 outcome | Resolved         |
|----------|----------------|-------------|--------------------------------------------------------|----------------|------------------|
| TW-W-1   | meta-fix       | 2026-04-22  | `make check-css-vars` should also catch `rgb()` calls  |                |                  |
| TW-W-2   | meta-wish      | 2026-04-23  | `make new-tool` scaffolder would cut onboarding to 10m |                |                  |
| TW-W-3   | meta-question  | 2026-04-24  | Should wishlist.md itself be grep-checked by verify?   |                |                  |
```

An optional `## Details` section below the table holds extended
content for entries needing more than the description column allows:

```markdown
## Details

### TW-W-2 — `make new-tool` scaffolder

Onboarding a new tool currently takes 40+ minutes across 8 locations
(CLAUDE.md, taxonomy.py, test fixtures, docs, etc.). A scaffolder
would take a tool name and generate the stub entries.

The tricky part is the test fixture — it has different shapes for
network vs. local tools. A scaffolder would need a --kind flag.
```

The `### TW-W-N —` heading is the lookup anchor. Grep for `TW-W-N`
finds both the table row and the details section.

### Column rules

| Column | Rule |
|---|---|
| `ID` | `TW-W-N` where N is monotonic within this file. The `W` segment distinguishes standalone entries from phase-file `TW-N` entries. |
| `Sub-type` | One of: `meta-fix`, `meta-question`, `meta-wish` (INV-WISHLIST-02). Same vocabulary as phase-file wishlist entries. |
| `Captured` | ISO date `YYYY-MM-DD`. The capture date — when `/reflect:grow` wrote the row. |
| `Description` | Under 100 characters. Frontload the concept. Imperative or noun-phrase form, not narrative. |
| `Step 6 outcome` | `APPLIED`, `DECLINED`, `DEFERRED`, or empty. Populated by `/reflect:full` sweep only. |
| `Resolved` | `{phase_id}` when promoted and closed; empty while pending. Populated by `/reflect:full` sweep only. |

### Append-only semantics

Entries are added to the bottom of the table during capture. **Never
rewrite existing rows.** The only modifications allowed mid-life:

- **Sweep step** writes to `Step 6 outcome` and `Resolved` columns
- **Reclassification** updates the `Sub-type` cell when the author
  changes their mind. Record the rationale in skill_dev_log.md if
  the pattern recurs (suggests classification discipline needs
  adjustment).

Promoted entries are marked `Resolved`, not deleted. This preserves
the audit trail that `/reflect:audit` reads.

### Validation

| Check | What it validates |
|---|---|
| Check 15 (meta-note sub-type coverage) | All wishlist entries — phase-file and standalone — have a valid sub-type from INV-WISHLIST-02 vocabulary |
| INV-WISHLIST-01 | Six-column shape preserved; column names exact |
| `/reflect:audit` orphan grep | Identifies entries with empty `Resolved` after 2+ full reflections elapsed |

See `reference/grow.md` for the workflow that writes to this file
and `reference/audit.md` for the diagnostic that reads it.

---

## Worked Example — One Lesson Flowing Through All Three Layers

This shows a single lesson being captured from phase file to INDEX to AI file.

### Step 1 — In the phase file (narrative source of truth)

```markdown
### 5. Passive detection-mode saves ~55s on every probe

Wpscan's default `mixed` detection mode runs `wp_version/unique_fingerprinting.rb`,
which probes 571 JS/CSS files to compute version checksums. This takes ~57s
before any real work begins — killing the 60s integration probe timeout.
In passive mode, wpscan reads the HTML once (~2s) and proceeds directly to
the password attack.

| Mode | Time | Use case |
|------|------|----------|
| mixed (default) | ~62s | Never in 60s probes |
| passive | ~9s | Always in integration probes |

**Lesson:** Add `--detection-mode passive` to every wpscan probe in a
≤60s timeout.
```

### Step 2 — In INDEX.md (discovery router)

Add one row to the **Active** tier:

```
| wpscan, testing, timing | Passive detection-mode saves ~55s on every probe; default mixed mode fingerprints 571 files before attacking | phase22_testing:5 | rule |
```

- Tags: primary tag first, comma-separated.
- Description: 119 chars (under 120), concept frontloaded.
- Source: `phase22_testing:5` — integer entry number only, no `.md`.
- Type: `rule` — prescriptive, violation causes predictable failure.

### Step 3 — In ai/wpscan.md (structured recall)

Add a new rule using the canonical plain-title format (`### Short imperative`).
Note: wpscan.md is the one file using legacy `### Rule N:` numbering — new
entries there may continue the numbering for consistency, but the canonical
format shown here is what every other AI file uses.

```markdown
### Always use --detection-mode passive in integration probes
<!-- tags: wpscan, testing, timing -->

**When:** Writing any wpscan probe in an integration test with a ≤60s timeout
**Rule:** Add `--detection-mode passive` to every wpscan probe. Default mixed
mode makes 571+ HTTP requests for version fingerprinting, taking ~57s before
the actual probe work begins.

```bash
# SLOW (default): ~57s fingerprinting + 5s attack = ~62s → timeout killed
wpscan --url http://target/ --usernames admin --passwords list.txt --password-attack wp-login

# FAST: ~2s base scan + 5s attack = ~9s → well within 60s
wpscan --url http://target/ --detection-mode passive --usernames admin \
    --passwords list.txt --password-attack wp-login
```

**Why:** The `wp_version/unique_fingerprinting.rb` phase probes 571 JS/CSS
files to compute version checksums. This dominates total scan time and
provides no value when the test only needs a password attack result.

*Source: phase22_testing:5*

---
```

### Step 4 — In ai/_overview.md (routing index)

Update the wpscan row's rule count and keywords:

```markdown
| [wpscan.md](wpscan.md) | 12 | passive detection mode (saves 55s), --enumerate u timing trap, ... |
```

### Isolation read check

Re-read only these three lines from the AI rule:

```
**When:** Writing any wpscan probe in an integration test with a ≤60s timeout
**Rule:** Add `--detection-mode passive` to every wpscan probe. Default mixed
mode makes 571+ HTTP requests for version fingerprinting, taking ~57s before
the actual probe work begins.
```

Does a future session that grep-hits only this rule heading get actionable
knowledge from those three lines alone? **Yes** — the When specifies the
exact context (integration probe with a 60s budget), the Rule specifies the
exact fix (add the flag), and the Rule's parenthetical justifies the fix
without requiring the Why line. This rule passes the isolation read.

If the isolation read had required loading the code block or the Why line
to be actionable, the rule would need to be rewritten.

---

## Deferred Features

These features existed in V3_3 but are deferred in V3_4 because zero or
near-zero repo usage does not justify the context tax:

- **Concern maps** — V3_3 documented concern maps as "the most efficient
  lookup path" but zero concern maps exist across 19 AI files. Feature
  removed from SKILL.md, verify.md, and _overview.md. Can be reintroduced
  in a future version if a real use case emerges.

If a future phase builds a genuine multi-rule design-concern cluster (3+
mutually-companioned rules addressing a shared architectural concern),
document it in a new phase file's "What Would Help Me Grow" section first
— that entry will seed the concern-map feature's reintroduction if it
proves worthwhile.
