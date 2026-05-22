---
name: lessons-learned_V3_6
description: >
  Capture and retrieve institutional knowledge from project work using
  a structured Lessons Learned system. This skill dispatches to ten
  sub-commands covering reflection, lookup, audit, between-phase
  capture, verification, export, bootstrap, and retroactive
  initialization. Trigger: user says "Reflect", "capture lessons",
  "what did we learn", "lessons learned", "retro", "retrospective",
  "post-mortem", "debrief", "knowledge transfer", "document this for
  next time", or asks to review what went well/poorly. Also trigger
  on sub-command invocations: /reflect, /reflect:full, /reflect:light,
  /reflect:lookup, /reflect:verify, /reflect:audit, /reflect:grow,
  /reflect:export, /reflect:bootstrap, /reflect:retroactive. Trigger
  when starting significant work on a project that has a
  lessons_learned/ directory — run the lookup protocol first. Trigger
  on undocumented `**Format:**` variant detection — route to the
  drift intake protocol. Trigger on requests to capture
  infrastructure-improvement ideas ("wishlist", "improvement ideas",
  "tooling gap"). Trigger on requests to assess feedback-loop health
  ("audit", "is the loop working", "are rules being followed",
  "REGRESSED"). Apply whenever the user wants to capture or retrieve
  institutional knowledge.
argument-hint: "[sub-command] [sub-command-args]"
allowed-tools: Read, Write, Edit, Grep, Glob, Bash(git:*), Bash(grep:*), Bash(awk:*), Bash(sed:*), Bash(md5sum:*), Bash(find:*), Bash(wc:*), Bash(sort:*), Bash(uniq:*), Bash(head:*), Bash(tail:*), Bash(diff:*), Bash(cat:*)
---

# Reflect — Lessons Learned Skill (V3.6)

Teaches a sub-command-dispatched workflow with two core modes:
**capture** (record knowledge after working) and **lookup** (retrieve
knowledge before working). Both use the same three-layer system
optimized for grep-based discovery. V3.6 introduces a sub-command
namespace, a between-phase capture path (`/reflect:grow`), and a
feedback-loop audit (`/reflect:audit`).

This system captures **project-level** institutional knowledge — what
was built, what broke, what was decided, and what infrastructure
improvements would help next time. For user preferences and personal
context, use your environment's memory or preferences system instead.

Read this document fully before writing or reading any entries. The
skill dispatches to ten sub-commands documented in §2; the per-sub-
command specs in §8 declare the exact files each sub-command reads
and writes.

---

## 1. System Architecture — Three Layers

The lessons learned system stores knowledge in three formats. Each is
optimized for a different access pattern.

### Layer 1: Phase Files (narrative source of truth)
**Location:** `lessons_learned/{phase_id}_{short_name}.md`
**Access pattern:** Read when you need the full story behind a rule.
**Format:** Markdown sections with numbered entries, tag comments, and
bold `**Lesson:**` takeaways. One file per major unit of work. Each
phase file declares a `**Format:**` variant on its header — see
`templates.md` §"Phase File Variants" for the three documented variants
(canonical, meta-reflection, case-study) or `reference/drift_intake.md`
for undocumented shapes.

### Layer 2: INDEX.md (grep-optimized discovery router)
**Location:** `lessons_learned/INDEX.md`
**Access pattern:** `grep` target. Every row is one self-contained line
with tags, description, source pointer, and type. A grep hit gives you
enough to decide whether to read deeper.
**Structure:** Three tiers — **Active** (recent), **Foundation** (proven
recurring), **Reference** (stable/completed).

### Layer 3: AI Subject Files (structured recall)
**Location:** `lessons_learned/ai/{topic}.md`
**Access pattern:** Read 1-2 targeted files for actionable rules in
**When/Rule** format. A cold-start session reads a topic file and gets
working knowledge without narrative overhead.
**Inventory:** `lessons_learned/ai/_overview.md` lists all files with
rule counts and topic keywords — grep this to find the right file.

**Relationship:** Phase files are the source of truth. INDEX.md points
into them. AI files extract actionable rules from them. A single lesson
appears in all three layers in different formats.

**Retrieval contract:** The structural properties that make grep-based
retrieval work are documented in `reference/invariants.md`. That file
names what must not drift; everything else is presentation and may
evolve. Read invariants.md before editing any skill file or when
Check 13, 16, or 17 fires.

**Meta-layer files** (`lessons_learned/meta/`) support workflow
capture and audit but are not part of the three-layer retrieval
surface:

- `meta/skill_dev_log.md` — skill-design decisions and meta-
  observations (read when making skill-design decisions)
- `meta/wishlist.md` — standalone infrastructure-improvement entries
  captured between phases via `/reflect:grow`. See `reference/grow.md`
  for the workflow and `reference/templates.md` §"Standalone Wishlist
  File Format" for the invariant (INV-WISHLIST-01).

---

## 2. Sub-Command Dispatch

The skill dispatches to ten sub-commands. Each maps to a focused
workflow with its own pre-loading, allowed-tools scope, and write
permissions. The full specs are in §8 Per-Sub-Command Specs.

### The ten sub-commands

| Sub-command | Purpose | Writes? |
|---|---|---|
| `/reflect` | Bare invocation — dispatches by state (see below) | depends on dispatch |
| `/reflect:full` | Full reflection at end of a work unit (Steps 1–6 from §4a) | Yes — phase file, INDEX.md, AI files, `_overview.md`, wishlist sweep |
| `/reflect:light` | Lightweight mid-session capture of a single lesson (§4b) | Yes — phase file, INDEX.md, AI file (appends only) |
| `/reflect:lookup <keywords>` | Retrieve relevant rules before working (§3) | No (reads only; tracks loaded rules to `/tmp/lookups_{phase_id}.md`) |
| `/reflect:verify` | Run the verify.md integrity checks | No (diagnostic only) |
| `/reflect:audit` | Feedback-loop health check — REGRESSED rules, unresolved meta-fixes, stale CF, orphaned wishlist. See `reference/audit.md`. | No (diagnostic only) |
| `/reflect:grow` | Capture an infrastructure-improvement idea between phases. See `reference/grow.md`. | Yes — appends to `meta/wishlist.md` |
| `/reflect:export` | Foundation-tier portable export at project completion (§9) | Yes — creates `lessons_learned/export.md` |
| `/reflect:bootstrap` | Initialize `lessons_learned/` scaffolding for a new project. See `reference/bootstrap.md`. | Yes — creates the directory structure |
| `/reflect:retroactive` | Initialize on a mature repo with existing history. See `reference/retroactive.md`. | Yes — creates structure + initial phase files |

### Bare `/reflect` dispatch

Invoking `/reflect` without an explicit sub-command dispatches by
state:

```
1. lessons_learned/ does not exist?       → /reflect:bootstrap
2. lessons_learned/ exists but empty
   AND project has 5+ commits of history? → /reflect:retroactive
3. Otherwise                               → /reflect:full
```

This is a convenience for the common case. Explicit sub-command
invocation always overrides state-based routing.

### Why sub-commands

Three benefits over the v3.5 monolithic skill:

1. **Context economy** — each sub-command loads only its relevant
   reference files. A `/reflect:lookup` invocation loads `lookup.md`
   plus INDEX.md and `_overview.md`, not all 11 reference files.
2. **Tool scoping** — read-only sub-commands (`:lookup`, `:verify`,
   `:audit`) cannot accidentally write. Capture sub-commands have
   tighter scopes per their actual needs.
3. **Discoverability** — the sub-command list (above) communicates
   what the skill can do without requiring a full read of SKILL.md.

### Sub-command invariant (INV-SUBCMD-01)

Every `/reflect:*` invocation must map to exactly one sub-command
defined in this section. Unknown sub-commands route to a help
message listing the ten valid sub-commands — never to a default
behavior. Check 17 (sub-command contract) validates that every
sub-command referenced in workflow text has a spec row in §8.

### When NOT to invoke a sub-command

Three cases where bare prose works better than explicit sub-command
invocation:

1. **First-time use on a project** — bare `/reflect` will state-route
   to `:bootstrap` or `:retroactive`, which is what you want.
2. **Spontaneous conversation about lessons** — natural-language
   trigger words ("retro", "post-mortem", "what did we learn") let
   the description-classifier route appropriately without forcing
   the user to remember sub-command names.
3. **Cross-skill invocation** — if another skill calls into
   lessons-learned, bare invocation is more natural than
   sub-command-specific calls.

---

## 3. Lookup Protocol — Retrieve Knowledge Before Working

This is how accumulated experience improves current work. At the start
of a new session, check whether `lessons_learned/` exists. If it does,
run a lookup scoped to the current task before writing code.

### When to look up
- **Always:** Before any task that creates, modifies, or deletes logic
- **Always:** When stuck on a problem or choosing between design options
- **Skip:** Formatting changes, documentation typos, dependency bumps
  with no behavioral change

### Choosing keywords
Pick 2-3 keywords from different angles of the task. Good keywords come
from three sources:

| Source | Example | Why it works |
|--------|---------|-------------|
| Technology/framework being touched | `sqlalchemy`, `docker`, `auth` | Matches the tag column in INDEX.md directly |
| Problem class (not the specific error) | `timeout`, `race-condition`, `validation` | Matches the description column — how lessons are worded |
| Architectural layer or concern | `api`, `migration`, `deploy`, `testing` | Catches cross-cutting rules that span technologies |

Avoid: specific variable names, error codes, file paths — these are too
narrow and won't match how lessons are written.

### Quick lookup
```bash
# 1. Search the index with 2-3 keywords from different angles
grep -i "keyword1\|keyword2" lessons_learned/INDEX.md
# 2. If hits: identify which AI file covers the topic
grep -i "keyword" lessons_learned/ai/_overview.md
# 3. Read that AI file; check **When:** and optional **Not when:** before
#    reading the full body. Skip the rule if a Not-when condition matches
#    your task.
# 4. Apply relevant rules before writing code
# 5. If a loaded rule has a **Companions:** line, load those rules too —
#    they address related facets the primary rule doesn't cover alone
```

### Deep lookup (when stuck or before major design decisions)
See `reference/lookup.md` §"Deep lookup commands" for the full command
set including cross-file grep, table-of-contents extraction, and
follow-source-to-phase-file patterns.

### Refining results

**Zero hits — broaden the search:** Check tag vocabulary; try synonyms
or broader problem classes; scan AI file headings. See
`reference/lookup.md` §"Refining zero hits" for specific command
patterns.

**Too many hits — narrow with piped grep or tier scoping.** See
`reference/lookup.md` §"Refining too many hits".

**Ambiguous hits — read only When/Not-when/Symptom lines to filter
cheaply.** See `reference/lookup.md` §"Ambiguous hit filtering".

### The grep contract

The load-bearing summary: INDEX rows, AI file headings, and _overview.md
are format-constrained so grep results are immediately useful. Full
explanation of why these formats work this way is in
`reference/lookup.md` §"The grep contract". The formats themselves are
defined in `reference/templates.md` and enforced as invariants (see
`reference/invariants.md` §INDEX.md and §AI Files).

**Token budget:** A quick lookup costs ~100-200 tokens (grep output +
one AI file section). A full reflection costs more but runs
infrequently. The system is designed so reading is cheap and writing is
thorough.

### Tracking what you load

**Open a running note file at session start.**
`/tmp/lookups_{phase_id}.md` captures which rules you consulted and
whether they influenced decisions. Without this, the Applied Lessons
feedback loop silently breaks — you won't remember at reflection time
which rules were consulted vs. missed.

**Format:** One line per rule consulted.
```
| file.md → "Rule Title" | applied | one-line note |
| file.md → "Rule Title" | in place | already done by prior code |
| file.md → "Rule Title" | N/A      | Not-when matched |
| memory:feedback_foo     | REGRESSED | knew it, didn't consult, broke it |
```

Outcome vocabulary (9 values): `applied | applied proactively |
in place | N/A | missed | REGRESSED | contradicted | revised |
discovered`. Definitions in `reference/templates.md` →
"Applied Lessons Table Format" → Outcome Vocabulary.

At reflection time, the note file feeds the Applied and Missed tables
directly.

---

## 4. Capture Workflows

### 4a. Full Reflection (end of a work unit)

A "phase" corresponds to a coherent unit of work with a definable scope
and outcome — typically a feature, a refactor, a testing pass, or an
incident response. If in doubt, one phase file per reflection is the
right default.

Read `reference/templates.md` before writing any entries — it has exact
formats for all three layers.

**Step 1 — GATHER (read-only)**
1. `git log --oneline -20` (or relevant range) for the work being reflected on
2. Review notes, test results, error messages from the session
3. **Run the evidence block** — execute the commands in
   `reference/evidence.md` §"The commands" and write output to
   `/tmp/evidence_{phase_id}.md`. Signals: churn histogram, error
   frequency, test delta. This feeds the completeness check in Step 2.
   **Note:** When invoked as `/reflect:full`, these commands
   pre-execute at invocation time via `!` interpolation — their
   output is already in context when Claude begins drafting. When
   invoked otherwise, run them manually.
4. **Sweep the standalone wishlist** — read
   `lessons_learned/meta/wishlist.md` if it exists. For each row
   with empty `Resolved`:
   - Reclassify the entry's sub-type with full-context judgment
     (apply the three-criterion test from
     `reference/meta_classification.md` against the current
     reflection's evidence)
   - Promote to the current phase file's "What Would Help Me Grow"
     section with a back-pointer (`*(originally TW-W-N in
     wishlist.md, captured {date})*`)
   - Mark `Resolved: {phase_id}` in wishlist.md (do not delete the
     row — the audit trail is read by `/reflect:audit`)
   - `meta-fix` entries become candidates for Step 6 below
   See `reference/grow.md` §"Integration with /reflect:full" for the
   full sweep semantics, including the uncommitted-changes deferral.
5. Identify which existing lessons were looked up or applied during this
   work — these feed the Applied Lessons section. Include rules that
   were consulted but turned out not to apply, and rules that *should*
   have been consulted but were missed (discovered only now in hindsight).
6. Read the most recent phase file for numbering and format continuity
7. Read `INDEX.md` — scan Active tier for existing coverage (avoid duplicates)
8. Identify which AI subject files are likely affected (1-3 files)

**Step 2 — DRAFT the phase file**
9. Determine the phase identifier (see naming convention in `reference/bootstrap.md`)
10. Write header with scope and date
11. **Declare `**Format:**` variant** on its own line in the header block
    (INV-PHASE-08). Choose from `canonical`, `meta-reflection`, or
    `case-study` — see `templates.md` §"Phase File Variants" for the
    decision guide. If none fit, propose a new variant name and follow
    `reference/drift_intake.md`.
12. **Applied Lessons:** Fill the table from the GATHER inventory
    (sub-step 5) and your `/tmp/lookups_{phase_id}.md` running note.
    One row per rule consulted. Outcome vocabulary in full:
    `applied | applied proactively | in place | N/A | missed |
    REGRESSED | contradicted | revised | discovered` — definitions
    and handling semantics in `reference/templates.md` → "Applied
    Lessons Table Format". REGRESSED is the most important outcome
    to capture honestly; it diagnoses lookup-protocol failure.
    For `contradicted` rules, see templates.md for supersession
    handling. Memory files are valid sources.
13. **Missed Lessons:** Separate table immediately after Applied
    Lessons — rules that should have been consulted but weren't,
    discovered only now in hindsight. The split forces a hindsight
    grep pass against INDEX.md. See templates.md → "Missed Table".
14. **What Went Well:** 3-5 entries for approaches that worked or
    decisions validated
15. **Bugs and Pitfalls:** Entries for each non-trivial bug. Focus on
    the *class* of bug, not the instance. Root cause and fix.
    **Every entry must have a `**Lesson:**` anchor line with at least
    one citation** (commit SHA, file:line, function name, specific
    count, specific test name, error string, or config/flag). See
    `reference/evidence.md` §"The Lesson Anchor" for content standards
    and anti-patterns.
16. **What Went Badly (optional):** Distinct from Bugs. Covers judgment
    calls that wasted effort, warnings ignored, stale assumptions.
    Include when the session had real friction the Bugs bucket didn't
    capture.
17. **Design Decisions:** Entries for non-obvious choices with tradeoffs.
    Same anchor discipline as Bugs — `**Lesson:**` with citation.
18. **Carry-Forward Items:** Open debt tracked in a table (see
    `reference/templates.md` → Carry-Forward Items Table Format).
    - Check prior phase files for unresolved CF items — mark any that
      were addressed in this phase: `RESOLVED in {current_phase_id}`
    - Carry unresolved items forward with their original CF number
19. **What Would Help Me Grow — Tooling Wishlist (optional but recommended):**
    Standing slot for "the skill, the tooling, or the environment itself
    needs X." Each wishlist entry declares a sub-type classification:
    `meta-fix` (bounded, actionable, known fix), `meta-question`
    (needs design thought), or `meta-wish` (new capability). See
    `reference/meta_classification.md` §"Three Sub-Types" for the
    three-criterion test. `meta-fix` entries feed Step 6 (synchronous
    proposal loop).
20. **Metrics:** Fill the metrics table (see `reference/templates.md`
    for options)
21. **Completeness check:** Before proceeding to INDEX update, run the
    check in `reference/evidence.md` §"The Completeness Check". Cross-
    reference top churned files / repeated error classes / test deltas
    from the evidence block against entries in the phase file. Each
    "not covered" is either a legitimate omission (no lesson) or a gap
    (add the entry). The check takes a few minutes proportional to
    reflection size and catches existence-gaps that drafting missed.

**Step 3 — UPDATE INDEX.md**
22. For each phase file entry, add one row to the **Active** tier
23. Use the entry's tags, a frontloaded description (under 120 chars),
    source pointer, and type classification. The four valid types are
    `rule | bug | pattern | insight` (see §5b).
24. Check for duplicates — if a rule already exists in INDEX.md, update
    its source pointer to add the new phase reference instead of
    creating a new row
25. At phase transitions, graduate old Active entries (see §5d for tier
    criteria).

**Step 4 — UPDATE AI subject files**
26. For each `rule`, `bug`, or `pattern` entry, write a When/Rule entry
    in the appropriate AI subject file (route by primary technology or
    concern). `insight` type entries may live only in phase file +
    INDEX.md.
27. **Isolation-read discipline.** After writing each AI rule, re-read
    only the rule's `**When:**`, optional `**Not when:**`, and
    `**Rule:**` lines in isolation from the surrounding narrative. If
    those three lines don't carry the rule without the code block or
    `**Why:**` line, the rule will be useless to a future session that
    grep-hits only the heading. Rewrite until isolation-read is
    self-contained.
28. For cross-cutting rules, add a short cross-reference in the
    secondary file: `See: {primary_file}.md → "{Rule Title}"` — do not
    duplicate the full rule
29. Review Applied Lessons from this and prior phases for companion
    candidates. Add `**Companions:**` lines to both rules (mutual
    linking). Keep lists to 1-3 entries.
30. Update rule counts in `_overview.md` and the INDEX.md Quick
    Reference table
31. Verify `_overview.md` Topics/Keywords still reflect each AI file's
    coverage
32. New AI file threshold: 3+ rules on uncovered topic → create + update
    `_overview.md` and INDEX.md Quick Reference
33. AI file size threshold: 30+ rules → split by subtopic; update all
    source pointers, `_overview.md`, and INDEX.md Quick Reference

**Step 5 — VERIFY**
34. Run the verification checks in `reference/verify.md`
35. **Skill Self-Review.** Run Checks 12 (reference pointer resolution),
    13 (format drift), and 16 (variant conformance) against this skill
    itself. If this reflection required a format the skill doesn't
    document, if any reference pointer in SKILL.md resolves to missing
    or duplicated content, if the skill describes a feature with zero
    real-world usage, or if a phase file declares an undocumented
    variant, classify the gap as `meta-fix`, `meta-question`, or
    `meta-wish` in the "What Would Help Me Grow" section.

**Step 6 — SYNCHRONOUS META-FIX LOOP**

The reflection's wishlist now includes both:
- Entries written directly in the phase file's Grow section (Step 2
  sub-step 19), and
- Entries promoted from `meta/wishlist.md` during the GATHER sweep
  (Step 1 sub-step 4), each with a back-pointer to the original
  standalone entry

For each `meta-fix` entry in this combined wishlist:

36. Draft the exact edit as a proposal (target file, current content if
    any, proposed content, rationale from the wishlist entry)
37. Present the proposal to the user for approve / decline / defer-to-
    meta-question decision
38. If approved: apply the edit immediately; annotate the wishlist entry
    with `**Step 6 outcome:** APPLIED — {brief note}`. If the entry was
    promoted from `meta/wishlist.md`, mirror the outcome to the
    standalone wishlist's `Step 6 outcome` column.
39. If declined: annotate the wishlist entry with `**Step 6 outcome:**
    DECLINED — {brief note on why}`; the entry remains in the wishlist
40. If deferred: reclassify the entry as `meta-question`; the entry
    feeds a future skill-development reflection

**Safety rules:**
- Current-project-only edits (no cross-skill synchronous changes)
- Defer if target file has uncommitted changes in this session
- Maximum 3 synchronous proposals per reflection (more suggests
  systemic drift — consider a dedicated skill-development reflection)
- No chained edits (each proposal is independent)

Full workflow details and edge cases in `reference/meta_classification.md`
§"Synchronous Step 6".

**If a reflection is interrupted** after writing the phase file but
before completing INDEX.md or AI file updates, run the verification
checks on the next session. Checks 1 and 2 will identify phase file
entries missing their INDEX.md rows or AI file rules. Complete the
missing updates before starting new work.

### 4b. Lightweight Capture (mid-session, single lesson)

When you discover something worth recording *right now* but a full
reflection would break flow:

1. Append one numbered entry to the **current** phase file (create one
   if none exists — use `reference/bootstrap.md` for the header and
   include a `**Format:**` declaration, leave other sections empty
   for now)
2. Ensure the entry has a `**Lesson:**` anchor with a citation (see
   `reference/evidence.md` §"The Lesson Anchor")
3. Add one INDEX.md Active row
4. Add one AI subject file rule
5. Skip Metrics, Carry-Forward, and the completeness check — those are
   for full reflection. If the lesson was triggered by a prior rule you
   looked up (or failed to look up), add a row to the Applied Lessons
   table (create the table if the phase file doesn't have one yet).
   Leave the Outcome column for full reflection if uncertain.

This keeps the three-layer contract intact without ceremony. When full
reflection runs later, it fills in the gaps.

### 4c. Conflict Avoidance

Before writing to any lessons learned file, check for concurrent changes:
```bash
# If lessons_learned/ is git-tracked:
git diff --name-only lessons_learned/
# If not git-tracked (new or excluded from repo):
ls -lt lessons_learned/*.md lessons_learned/ai/*.md 2>/dev/null | head -10
```
If files have changed since your last read, re-read before appending.
Append to the end of sections — never rewrite existing entries.

---

## 5. Decision Trees

### 5a. "Is this worth recording?"

**RECORD if:**
- A future session would need this to avoid repeating the mistake
- The fix required understanding not obvious from the code or commit
- A pattern emerged that applies beyond this specific instance
- A decision was made between alternatives with non-obvious tradeoffs
- Something worked unexpectedly well and the approach should be repeated

**When recording, also consider:** If this rule uses broad keywords
that could match unrelated contexts in this project, define a
`**Not when:**` boundary in the AI file entry. Check Applied Lessons —
if a prior rule was frequently marked `not applicable`, it likely needs
a Not-when added.

**DO NOT RECORD:**
- Facts derivable from reading current code or `git log`
- The debugging journey — record only what worked and why
- Ephemeral task details (retried a command, changed a file path)
- Operational incidents without structural lessons
- Library version choices without non-obvious compatibility constraints

### 5b. "What type is this?"

| Type | Definition | Example |
|------|-----------|---------|
| **rule** | Prescriptive: "always X" or "never Y." Violating causes predictable failure. | "Validate UUID before any DB query" |
| **bug** | Specific failure encountered and fixed. Record failure mode + root cause. | "Batch insert silently drops rows over 1000" |
| **pattern** | Reusable approach that worked. Not prescriptive — alternatives exist. | "Fixture-driven parser testing" |
| **insight** | Meta-observation about process, architecture, or methodology with no single prescriptive action. Lives in phase file + INDEX.md; does not always route to an AI file. | "Coverage 97→99% needs infra changes, not more unit tests" |

**Default to `rule`** when uncertain. Most entries are rules. Use
`insight` only when the observation is genuinely process-level and
doesn't resolve to a When/Rule line — if you can phrase it
prescriptively, it's a rule.

### 5c. "Which AI subject file?"

Route by the **primary** technology or concern. Use the project's
existing AI files as the routing table:
```bash
cat lessons_learned/ai/_overview.md
```

General routing principles:
- Lesson about how a specific technology behaves → `{technology}.md`
- Testing any technology → `testing.md`
- Process/methodology regardless of tech → `process.md`
- Security regardless of tech → `security.md`
- Cross-cutting rules → write the full When/Rule entry in the
  **primary** file. In the secondary file, add only a one-line
  cross-reference at the bottom under a `## See Also` heading:
  `- See: security.md → "Sanitize inputs at all database boundaries"`

**New file vs. new section:** If a topic is a specialization of an
existing file, add a `##` section header within the existing file until
the subtopic crosses 3 rules. At 3+ rules, split it into its own file.

### 5d. "Which INDEX.md tier?"

| Tier | Criteria |
|------|----------|
| **Active** | From current or recent work (last 2 phases). New entries always start here. |
| **Foundation** | Recurred across 2+ phases, or universal (security, validation). Graduate from Active when proven durable. |
| **Reference** | From completed, stable work. Graduate when tag is inactive for 2+ phases AND the work area is complete. |

**Graduation at phase transitions:**
- **Active → Foundation:** Active rows with multi-phase source pointers
  (e.g., `phase03_auth:2, phase07_api:4`) were reinforced by duplicate
  detection in capture Step 23. Multi-phase sources → Foundation.
- **Foundation → Reference:** Requires both conditions — (a) no new
  entries with that tag in last 2 phases, AND (b) underlying work area
  is completed or stable. Tag inactivity alone is not sufficient; a
  stable but actively consulted tag (e.g., security) stays in
  Foundation.

### 5e. "Which variant?"

| Kind of work | Variant | Key signal |
|---|---|---|
| Single unit of work, reflecting on what just happened | `canonical` | Default. Populated Applied Lessons table. |
| Reviewing multiple phases at once for arc-level patterns | `meta-reflection` | No per-phase Applied/CF tables — they already exist in constituent phases. |
| Writing teaching artifact for future sessions doing similar work | `case-study` | Descriptive section headings rather than canonical section names. |
| None of the above; something genuinely new | Drift Intake Protocol | See `reference/drift_intake.md`. |

Full variant schemas in `templates.md` §"Phase File Variants".

---

## 6. Anti-Patterns — What NOT to Save

- **"Fixed the import error"** — Only record if it reveals a systemic pattern.
- **"Tried X, didn't work, tried Y"** — Record only Y and why. The journey is ephemeral.
- **"Changed file X line 42"** — Git knows the what. Record the WHY.
- **"Service was down, restarted it"** — Only record if it reveals a missing health check.
- **Duplicating an existing rule** — grep INDEX.md first. If it exists, update the source pointer.
- **Saving patterns visible in the code** — The codebase documents itself. Record what isn't obvious from reading the implementation.
- **Lesson lines that restate the title** — A `**Lesson:**` anchor must carry actionable content beyond the title. See `reference/evidence.md` §"Anti-patterns".

---

## 7. Quick Reference Card

```
SUB-CMDS:   /reflect (bare → :full or state-routed) | :full | :light | :lookup <kw>
            :verify | :audit | :grow | :export | :bootstrap | :retroactive
DISPATCH:   bare /reflect → no LL dir? :bootstrap; empty LL + 5+ commits? :retroactive; else :full
LOOKUP:     grep INDEX.md → grep _overview.md → filter When/Not-when → follow Companions → track in /tmp/lookups_{phase}.md
CAPTURE:    evidence (pre-exec on :full) → wishlist sweep → phase file → completeness check → INDEX.md → ai/{topic}.md → companions → _overview.md → skill self-review → Step 6
Sections:   Applied / Missed / Well / Bugs / Badly? / Decisions / CF / Grow? / Metrics
Entry:      ### N. Title  /  <!-- tags: -->  /  narrative  /  **Lesson:** {citation}
Anchor:     **Lesson:** line on every Bugs/DD entry — cite commit / file:line / function / count / test name
INDEX row:  | tags | description (<120ch, frontloaded) | phase_id:N | rule|bug|pattern|insight |
AI rule:    ### Imperative Title  /  <!-- tags: -->  /  **When:**  /  **Not when:**  /  **Rule:**  /  code  /  **Why:**  /  Companions  /  *Source: phase_id:N*  /  ---
Isolation:  Re-read When / Not-when / Rule in isolation after authoring — must stand alone
Not-when:   One-line boundary — skip rule if task matches (add when keywords overlap unrelated contexts)
Companion:  **Companions:** file.md → "Rule Title"  (mutual, 1-3 max)
Applied:    | rule (file → heading or memory:name) | outcome | note |
Outcomes:   applied | applied proactively | in place | N/A | missed | REGRESSED | contradicted | revised | discovered
Format:     **Format:** canonical | meta-reflection | case-study — declared in phase file header
Variants:   see templates.md §Phase File Variants; undocumented → reference/drift_intake.md
Evidence:   churn + errors + test-delta → /tmp/evidence_{phase_id}.md (pre-exec on :full via ! interpolation)
Complete:   after drafting, cross-check top churned / error classes / tests against entries
Meta:       **Sub-type:** meta-fix | meta-question | meta-wish — classify at authorship
Wishlist:   meta/wishlist.md (between-phase capture via /reflect:grow) — 6 cols, append-only
Sweep:      /reflect:full GATHER step 4 promotes wishlist.md entries to phase Grow section, marks Resolved
Step 6:     meta-fix → synchronous edit proposal (max 3 per reflection, current-project only)
Audit:      /reflect:audit → 4 greps (REGRESSED trend, unresolved meta-fix, stale CF, orphaned wishlist) — see reference/audit.md
Supersede:  **Superseded by:** file.md → "New Rule"  /  **Supersession reason:** corrected|refined|narrowed|split
Cross-ref:  See: {file}.md → "{Rule Title}"  (in secondary file's See Also)
Types:      rule | bug | pattern | insight
Tiers:      Active → Foundation → Reference  (graduation criteria in §5d)
CF:         Table format (CF-N as ID column), not line prefix  /  mark RESOLVED in {phase_id}
New file:   3+ rules on uncovered topic → create + update _overview + INDEX
Split:      30+ rules in one AI file → split by subtopic
Bootstrap/Retroactive: see reference/bootstrap.md and reference/retroactive.md
Self-review: Check 12/13/16/17 fire? → classify meta-fix | meta-question | meta-wish → Step 6 for meta-fix
```

---

## 8. Per-Sub-Command Specs

This is the contract Check 17 (sub-command contract) validates. Every
sub-command referenced in §2 must appear in this table with allowed-
tools, pre-load list, and write list specified.

| Sub-command | Pre-executes (`!`) | Pre-loads (`@`) | Allowed-tools | Writes |
|---|---|---|---|---|
| `/reflect` (bare) | evidence block | INDEX.md, _overview.md, latest phase file | Read, Grep, Glob, Edit, Bash(git:*) | dispatches by state to `:full`, `:bootstrap`, or `:retroactive` |
| `/reflect:full` | evidence block (churn, errors, test-delta) | INDEX.md, _overview.md, latest phase file, templates.md, meta/wishlist.md, /tmp/lookups_{phase_id}.md | Read, Grep, Glob, Edit, Bash(git:*) | phase file (new), INDEX.md (append), AI files (append), _overview.md (update counts), meta/wishlist.md (sweep marks Resolved) |
| `/reflect:light` | — | templates.md, latest phase file | Read, Edit | phase file (append), INDEX.md (append), AI file (append) |
| `/reflect:lookup $ARGUMENTS` | — | INDEX.md, _overview.md, lookup.md | Read, Grep, Glob | /tmp/lookups_{phase_id}.md (append running note) |
| `/reflect:verify` | — | verify.md | Read, Grep, Glob, Bash(grep/awk/md5sum) | nothing (diagnostic only) |
| `/reflect:audit [rule_id]` | four loop-health greps | INDEX.md, _overview.md, meta/wishlist.md, audit.md | Read, Grep, Glob, Bash(grep/awk) | nothing (diagnostic only) |
| `/reflect:grow` | — | templates.md, meta_classification.md, grow.md, meta/wishlist.md | Read, Edit | meta/wishlist.md (append only) |
| `/reflect:export` | — | INDEX.md, AI files (Foundation-tier) | Read, Write | lessons_learned/export.md (create or overwrite) |
| `/reflect:bootstrap` | — | bootstrap.md | Read, Write | lessons_learned/ scaffold (creates directory tree, INDEX.md, _overview.md, meta/wishlist.md, meta/skill_dev_log.md) |
| `/reflect:retroactive` | git log summary | retroactive.md, bootstrap.md | Read, Write, Grep | lessons_learned/ scaffold + initial phase files extracted from history |

### Allowed-tools rationale

The frontmatter `allowed-tools` declares the *union* of all
sub-command needs. The per-sub-command scopes above are
*disciplines* — they describe what each sub-command should and
should not touch. A misfiring sub-command that respects its scope
cannot corrupt files outside that scope.

**Read-only sub-commands:** `:lookup`, `:verify`, `:audit`. These
must not write to `lessons_learned/` files. Their only write target
is `/tmp/lookups_{phase_id}.md` (lookup), and that file is ephemeral.

**Append-only sub-commands:** `:light`, `:grow`. These add new
content but do not modify existing entries. INV-WISHLIST-01's
append-only semantics depend on `:grow` respecting this discipline.

**Full-write sub-commands:** `:full`, `:export`, `:bootstrap`,
`:retroactive`. These create new files or modify existing ones in
defined ways. Each has tighter scope than "edit anything in
`lessons_learned/`" — see the per-sub-command write column above.

### When a sub-command exceeds its scope

If a `/reflect:lookup` invocation discovers that an INDEX.md row is
malformed (e.g., wrong column count) and would normally trigger a
fix:
1. The fix is a `meta-fix` for `/reflect:full` to apply, not a
   write `:lookup` should perform.
2. Capture the observation via `/reflect:grow` (which is allowed to
   write to `meta/wishlist.md` — the appropriate write target).
3. Continue the lookup. The malformed row is a known issue; the
   sweep at `/reflect:full` will adjudicate.

This discipline prevents diagnostic sub-commands from becoming
silent-fix tools, which would erode the trust that diagnostic output
reports honest state.

---

## 9. Project Completion — Portable Export

Run this at project completion or before handoff/archiving.

When a project is finished, its Foundation-tier lessons are the most
valuable output — proven rules that apply beyond this specific codebase.
To carry them into future projects:

1. Extract all Foundation-tier rows from INDEX.md into
   `lessons_learned/export.md`
2. Include the corresponding AI file rules (full When/Rule entries)
3. Strip project-specific source pointers — the rules now stand on
   their own
4. The export file can seed a new project's lessons learned system at
   bootstrap

---

## 10. Reference Files

Read these as needed — they are not loaded automatically. Sub-commands
specify which references they pre-load (see §8).

| File | Read when... |
|------|-------------|
| `reference/templates.md` | Before writing any lesson entries (exact formats, variant schemas, standalone wishlist format) |
| `reference/invariants.md` | Before editing the skill; when Check 13, 16, or 17 fires; when proposing a new variant |
| `reference/bootstrap.md` | `/reflect:bootstrap` — initializing lessons learned on a new project |
| `reference/retroactive.md` | `/reflect:retroactive` — adding lessons learned to a project with existing history |
| `reference/verify.md` | `/reflect:verify` — running integrity checks; Step 5 of `/reflect:full` |
| `reference/lookup.md` | `/reflect:lookup` — deep lookup, refining zero/many/ambiguous hits, grep contract explanation |
| `reference/evidence.md` | Before authoring Bugs/DD entries; when Check 14 fires; running the completeness check |
| `reference/meta_classification.md` | When authoring wishlist entries; running Step 6 synchronous loop; when Check 15 fires |
| `reference/drift_intake.md` | When a phase file shape doesn't fit documented variants |
| `reference/grow.md` | `/reflect:grow` — between-phase capture; sweep semantics during `/reflect:full` GATHER |
| `reference/audit.md` | `/reflect:audit` — feedback-loop health diagnostic |
| `lessons_learned/meta/skill_dev_log.md` | When making skill-design decisions or recording meta-observations |
| `lessons_learned/meta/wishlist.md` | Read by `/reflect:full` (sweep), `/reflect:audit` (orphan detection); written by `/reflect:grow` |

### Prove-first before shipping a change to this skill

Before shipping a new version of this skill, run the full
`reference/verify.md` against the current repo. Every format the skill
documents must be grep-checkable against real usage. If a documented
feature has zero real-world hits, it's a candidate for deletion. If the
repo uses a format the skill doesn't document, the skill is drifting —
either update the skill to match the repo or update the repo to match
the skill, whichever is more honest.

**V3.5 note:** Prove-first discipline applies differently to
measurable features (where a specific metric like "30% citation
density improvement" is the test) than to developmental features
(where the feature creates conditions for a capability to grow over
time). The metacognition classification and synchronous loop introduced
in V3.5 are developmental — their success is measured across months
of use rather than a single threshold. See
`lessons_learned/meta/skill_dev_log.md` for the full treatment and
the meta-observations recorded during V3.5 design.

**V3.6 note:** V3.6 is primarily an architectural revision. The
sub-command namespace, between-phase capture (`/reflect:grow`), and
feedback-loop audit (`/reflect:audit`) are all *enabling* changes —
they create conditions for tighter loop closure rather than
delivering measurable improvements directly. Trial measurement
follows the developmental pattern from V3.5: signals tracked in
`reference/grow.md` §"Signals the workflow is working" and
`reference/audit.md` §"Signals the audit is working".

**V3.6 also fixes three v3.5 drift issues** discovered during the
revision: missing `templates.md` §"Phase File Variants" section
(referenced in 3 places, never authored), missing `verify.md`
Checks 14, 15, and 16 (referenced across SKILL.md, evidence.md, and
meta_classification.md, never implemented). These were caught
because the v3.6 revision applied Check 12 (reference pointer
resolution) to v3.5 itself — exactly the prove-first pattern v3.5
introduced.

This is the prove-first discipline from `scripting-standards_V4_6`
applied to this skill. The V3.3 → V3.4 revision existed because
V3.3 shipped without it. The V3.4 → V3.5 revision added retrieval
invariants, variant taxonomy, drift intake, anchor discipline, and
meta-note classification. The V3.5 → V3.6 revision adds sub-command
dispatch, between-phase capture, feedback-loop audit, and (because
Check 12 caught it) the three reference-pointer drifts that V3.5
shipped with — each change recorded in skill_dev_log.md with its
prove-first trail. Don't repeat the mistake: the skill that teaches
prove-first must follow it on itself.
