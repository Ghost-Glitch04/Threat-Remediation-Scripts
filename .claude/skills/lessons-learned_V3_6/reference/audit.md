# Audit — Feedback Loop Health Check

## What this file is

This file documents `/reflect:audit`, the diagnostic sub-command for
**making invisible leakage in the lessons-learned feedback loop
visible**. It covers:

1. **Why audit exists** — the loop's health was previously
   unobservable, and unobserved systems silently degrade.
2. **The four greps** that comprise the audit, each with command,
   surfaced signal, interpretation, and action thresholds.
3. **Rule-specific mode** (`/reflect:audit <rule_id>`) for deep-dive
   diagnostics on a single rule's history.
4. **Cadence** — when to run audit, and what cadence signals about
   the loop's health.
5. **The audit report format** — a Metrics-table-shaped output that
   integrates with phase-file Metrics if desired.

Read this file:
- Before running `/reflect:audit` for the first time on a project
- When audit output flags a signal whose interpretation is unclear
- When tuning the thresholds for stale, orphaned, or REGRESSED
  signals to match a project's pace

This file works alongside `reference/verify.md` (which validates
*structural* integrity — Checks 1-17) and `reference/meta_classification.md`
(which owns the `**Step 6 outcome:**` annotation that audit reads).
Audit is the *behavioral* counterpart to verify: verify checks
that the system is structurally sound; audit checks that the system
is actually doing what it was designed to do.

---

## Why `/reflect:audit` Exists

V3.5 designed an explicit feedback loop:

```
work → look up rules → apply rules → capture outcomes → reflect →
update rules → next work uses better rules
```

Each step has a documented mechanism. The lookup protocol, Applied
Lessons table, AI rule format, REGRESSED outcome vocabulary, Step 6
synchronous loop — all of these together form a system that *should*
turn experience into compounding institutional knowledge.

But "should" and "does" can drift apart silently. Three failure modes
that V3.5 cannot self-detect:

**Failure mode 1: Rules that keep regressing.** A rule was captured.
It was looked up in subsequent phases. It was marked REGRESSED in
multiple Applied Lessons tables. The loop *should* have escalated
the rule (rewrite, move to memory, adjust trigger keywords) — but
nobody connected the dots across phases.

**Failure mode 2: Meta-fixes that never apply.** A wishlist entry
was classified `meta-fix`. Step 6 ran. The user deferred. The entry
sat in the wishlist for months. The synchronous loop's promise of
"fixes apply within minutes" silently failed for that entry.

**Failure mode 3: Carry-forward debt that compounds.** A CF item was
opened. It was carried forward 5 phases without resolution. Each
phase the author noted "still open," but no phase made it the
priority. The CF graduated from "open debt" to "permanent feature of
the wishlist."

In each case, the *individual* events are visible — the REGRESSED
mark, the deferred outcome, the carry-forward. But the *pattern*
across events is invisible without an explicit aggregation pass.
`/reflect:audit` is that aggregation pass.

---

## The Four Greps

Each grep surfaces one class of feedback-loop leakage. Audit runs
all four; the report presents them together as a single diagnostic.

### Grep 1: REGRESSED rule trend

**Surfaces:** Rules that were known but violated 2+ times across
phases. These are direct lookup-protocol failures on specific rules.

**Command:**

```bash
# Extract all Applied Lessons rows with REGRESSED outcome
grep -hE "REGRESSED" lessons_learned/phase*.md \
  | grep -E "^\| " \
  | awk -F'|' '{print $2}' \
  | sed 's/^ *//;s/ *$//' \
  | sort | uniq -c | sort -rn
```

**Output shape:**

```
   3 process.md → "Lookup-before-work"
   2 testing.md → "Mock fidelity validation"
   1 docker.md → "Container hostname resolution"
   ...
```

**Interpretation:**

| Count | Meaning | Action |
|---|---|---|
| 1 | Single regression, isolated | Watch; no action yet |
| 2 | Pattern emerging | Review the rule — too vague? Wrong file? Wrong keywords? |
| 3+ | Systemic lookup failure on this rule | Escalate: rewrite, move to memory, or split — this rule isn't being found at the right moments |

**Threshold for escalation: 3.** A rule regressed 3+ times needs
intervention — the loop is not closing on it.

### Grep 2: Unresolved meta-fix entries

**Surfaces:** Wishlist entries classified `meta-fix` with no
`**Step 6 outcome:**` annotation. These are synchronous-loop
candidates that silently never ran, or ran and were forgotten.

**Command:**

```bash
# Find all meta-fix wishlist entries across phase files and standalone
# wishlist, then check for Step 6 outcome annotations within each
# entry's body (typically the next 30 lines after the sub-type tag).

for f in lessons_learned/phase*.md lessons_learned/meta/wishlist.md; do
  [ -f "$f" ] || continue
  awk '
    /meta-fix/ { id=$0; line=NR; have_outcome=0 }
    /\*\*Step 6 outcome:\*\*/ && line>0 && NR-line<=30 { have_outcome=1 }
    /^### / && line>0 && NR-line>2 && !have_outcome {
      print FILENAME": "id; line=0
    }
    END { if (line>0 && !have_outcome) print FILENAME": "id }
  ' "$f"
done
```

**Output shape:**

```
phase76_modal_fix.md: ### TW-3 — E2E xfail marking — `meta-fix`
phase80_taxonomy.md: ### TW-80-4 — Delete-rule preflight helper — `meta-fix`
meta/wishlist.md: ### TW-W-2 — make new-tool scaffolder — `meta-fix`
```

**Interpretation:**

Each row is a meta-fix that should have been resolved synchronously
but wasn't. Three causes are common:

| Cause | Signal | Action |
|---|---|---|
| Step 6 was skipped during reflection | All meta-fix entries in one phase lack outcomes | Run Step 6 retroactively, or document why it was skipped |
| Wishlist sweep was skipped on a `/reflect:full` | Standalone-wishlist meta-fix entries lack outcomes after a full reflection ran | Re-sweep, or commit to running sweep next time |
| Misclassification | Single entries lack outcomes — the user repeatedly chose "defer to meta-question" | Reclassify the entries; their classification was wrong |

**Threshold for escalation: 3+ unresolved meta-fix entries.** Per
meta_classification.md §"Edge case 4," 3+ deferred items signal
systemic drift — consider a dedicated skill-development reflection.

### Grep 3: Stale carry-forward items

**Surfaces:** CF items unresolved across 3+ phases. These are
debt items that have transitioned from "open debt" to "permanent
fixture."

**Command:**

```bash
# Extract all CF rows from Carry-Forward sections, group by ID
for f in lessons_learned/phase*.md; do
  phase=$(basename "$f" .md)
  sed -n '/^## Carry-Forward/,/^## /p' "$f" \
    | grep "^| CF-" \
    | awk -v p="$phase" -F'|' '{
        gsub(/^ +| +$/, "", $2)
        gsub(/^ +| +$/, "", $3)
        resolved=($3 ~ /RESOLVED/) ? "RESOLVED" : "OPEN"
        print $2 "\t" p "\t" resolved
      }'
done | sort | awk -F'\t' '
  {
    cf=$1; phase=$2; status=$3
    if (status == "RESOLVED") { delete pending[cf]; next }
    if (!(cf in first_seen)) first_seen[cf] = phase
    pending[cf]++
    last_seen[cf] = phase
  }
  END {
    for (cf in pending) {
      if (pending[cf] >= 3)
        printf "%s: pending across %d phases (first: %s, latest: %s)\n",
               cf, pending[cf], first_seen[cf], last_seen[cf]
    }
  }
'
```

**Output shape:**

```
CF-3: pending across 5 phases (first: phase77_carryforward, latest: phase82_taxonomy)
CF-79-2: pending across 3 phases (first: phase79_indicator, latest: phase82_taxonomy)
```

**Interpretation:**

A CF item carrying for 3+ phases is likely one of:

| Situation | Resolution path |
|---|---|
| The work is genuinely lower priority than every subsequent phase's scope | Acknowledge: change priority to `Low` and add a re-evaluation date; or close the CF as "deferred indefinitely" with a note |
| The work is harder than originally scoped | Split the CF into smaller resolvable units, or escalate priority |
| The CF is dead — the underlying need disappeared | Close with `RESOLVED in {phase_id}: obsolete (reason)` |

**Threshold for action: 3 phases pending.** This is when the CF
graduates from "we'll get to it" to "we won't get to it without
intervention."

### Grep 4: Orphaned wishlist entries

**Surfaces:** Standalone wishlist entries with empty `Resolved` and
empty `Step 6 outcome` columns, older than 2 full reflections. These
are grow captures that accumulated without being swept.

**Command:**

```bash
# Read the standalone wishlist file, find rows with empty Resolved
# and Step 6 outcome columns, count phases since capture date

awk -F'|' '
  /^\| TW-W-/ {
    gsub(/^ +| +$/, "", $4)  # Captured
    gsub(/^ +| +$/, "", $6)  # Step 6 outcome
    gsub(/^ +| +$/, "", $7)  # Resolved
    if ($6 == "" && $7 == "") {
      gsub(/^ +| +$/, "", $2)  # ID
      print $2 "\t" $4 "\t(captured " $4 ", no sweep yet)"
    }
  }
' lessons_learned/meta/wishlist.md

# Count full reflections since each capture date (requires comparing
# against phase file timestamps or git log)
git log --pretty=format:"%ai %s" -- lessons_learned/phase*.md \
  | head -10
```

**Output shape:**

```
TW-W-1   2026-04-02   (captured 2026-04-02, no sweep yet)
TW-W-3   2026-04-08   (captured 2026-04-08, no sweep yet)
```

**Interpretation:**

If `/reflect:full` ran 2+ times since the capture date and the entry
was not swept, the sweep step is being skipped. This typically means
one of:

| Cause | Signal | Action |
|---|---|---|
| The sweep step was overlooked during GATHER | All entries from before a recent reflection are orphaned | Re-run sweep on the standalone wishlist; commit to including sweep in GATHER |
| The author is using grow as a parking lot | Many entries accumulate without ever being swept, regardless of full reflections | Review whether the entries are real wishlist material or noise; consider stricter capture discipline |
| Wishlist sweep is failing silently | Sweep started but error mid-way; entries partially swept | Check git log for partial wishlist edits; manually clean up |

**Threshold for action: 2 full reflections elapsed without sweep.**

---

## Rule-Specific Mode — `/reflect:audit <rule_id>`

A targeted deep-dive on one rule's history. Useful when an audit
report flags a rule and the author needs full context before
deciding intervention.

### What it surfaces

For the specified rule:

1. **Source phase entry** — the original phase file entry where the
   rule was captured
2. **AI file rule** — the current When/Rule statement
3. **INDEX.md row** — current tier, source pointer, type
4. **Applied Lessons history** — every Applied table row across all
   phase files where this rule appears, with outcome
5. **Companion network** — rules with mutual `**Companions:**` links
6. **Supersession chain** — if the rule was superseded or supersedes
   others, the full chain
7. **Memory file references** — if the rule appears in any memory
   file, the references

### Command

```bash
# Identify by AI file rule heading or INDEX description match
RULE_ID="$1"  # e.g., "Lookup-before-work" or "process.md:Lookup-before-work"

# 1. Phase entry
grep -rn "$RULE_ID" lessons_learned/phase*.md

# 2. AI file rule
grep -rA 30 "^### .*${RULE_ID}" lessons_learned/ai/

# 3. INDEX.md row
grep -i "$RULE_ID" lessons_learned/INDEX.md

# 4. Applied Lessons history
grep -B 1 -A 0 "$RULE_ID" lessons_learned/phase*.md \
  | grep -E "phase|REGRESSED|applied|missed|in place|N/A|contradicted|revised|discovered"

# 5. Companion network
grep -rA 1 "$RULE_ID" lessons_learned/ai/ \
  | grep -E "Companions:"

# 6. Supersession chain
grep -rA 5 "$RULE_ID" lessons_learned/ai/ \
  | grep -E "Superseded|Supersedes"

# 7. Memory references (if applicable to project)
grep -r "$RULE_ID" memories/ 2>/dev/null
```

### Use cases

- **Diagnosing a high-REGRESSED rule:** Pull the rule's full history,
  look at the trigger keywords, see whether the rule's `**When:**`
  line matches the contexts where it was missed.
- **Pre-supersession review:** Before superseding a rule, audit it
  to ensure the new rule covers all the contexts the old one was
  applied in (and was missed in).
- **Companion network check:** Visualize whether a rule's companion
  links are mutual and whether the network covers the design concern.
- **Memory-vs-AI-file routing decision:** If a rule is regressing in
  AI files, audit may show the project's memory file *also* has it
  — escalation may not be the right move; the lookup protocol may
  need fixing instead.

---

## Cadence — When to Run Audit

### Default cadence

**Every 5 full reflections.** This batches enough phase data to make
trends visible without making audit a per-phase ritual.

### Trigger-based cadence

Run audit immediately when any of these signal:

- A phase's Applied Lessons table has 2+ REGRESSED rows
- 3+ wishlist entries are deferred from a single Step 6 invocation
- The `/reflect:full` workflow felt like it was producing the same
  observations as the previous reflection
- A skill-development reflection is being scoped — audit precedes
  the design work

### What audit cadence reveals

Cadence itself is a signal:

| Cadence pattern | Interpretation |
|---|---|
| Every 5 phases, no trigger-based runs | Healthy. Loop is closing on its own. |
| Every 5 phases, occasional trigger-based runs | Healthy. Audit is catching real signals. |
| Trigger-based runs every 1-2 phases | Loop is leaking faster than scheduled audits can catch. Increase frequency. |
| Audit hasn't run in 10+ phases | The default cadence has lapsed. Loop health is unobservable. |

---

## The Audit Report Format

Audit output uses the same column shape as the phase-file Metrics
table, so audit findings can be pasted into a phase file's Metrics
section if a full reflection is paired with the audit.

```markdown
## Audit Report — {date}

### Summary

| Metric | Value |
|--------|-------|
| Phases reviewed | 8 (phase76 through phase83) |
| REGRESSED rules (count ≥3) | 1 |
| Unresolved meta-fix entries | 3 |
| Stale CF items (≥3 phases) | 2 |
| Orphaned wishlist entries (≥2 reflections) | 1 |

### REGRESSED rules

| Rule | Count | Latest phase | Action |
|------|-------|--------------|--------|
| process.md → "Lookup-before-work" | 4 | phase82_taxonomy | ESCALATE — rewrite or move to memory |

### Unresolved meta-fix entries

| Entry | Source | Captured | Action |
|-------|--------|----------|--------|
| TW-3 — E2E xfail marking | phase76_modal_fix | 2026-04-15 | Re-run Step 6 |
| TW-80-4 — Delete-rule preflight helper | phase80_taxonomy | 2026-04-19 | Re-run Step 6 |
| TW-W-2 — make new-tool scaffolder | meta/wishlist.md | 2026-04-22 | Sweep on next /reflect:full |

### Stale CF items

| ID | First seen | Latest seen | Phases pending | Action |
|----|------------|-------------|----------------|--------|
| CF-3 | phase77_carryforward | phase82_taxonomy | 5 | Resolve, split, or close as deferred |
| CF-79-2 | phase79_indicator | phase82_taxonomy | 3 | Re-evaluate priority |

### Orphaned wishlist entries

| ID | Captured | Sweep opportunities missed | Action |
|----|----------|----------------------------|--------|
| TW-W-1 | 2026-04-02 | 3 | Sweep on next /reflect:full |
```

This is reference material for the author's intervention decisions.
Audit does not write to any file; the report is the entire output.

---

## Anti-Patterns — What Audit Should NOT Do

**Anti-pattern 1: Audit applies fixes.** Audit is read-only by design.
If the four greps suggest interventions, the author runs the relevant
sub-command (`/reflect:full` for sweep, manual rule rewrite for
escalation). Mixing diagnosis and action concentrates risk in one
sub-command and erodes the trust that audit reports are honest
diagnostics rather than self-justifications.

**Anti-pattern 2: Audit suppresses signals to look healthy.** If a
phase's data shows the loop is leaking, the audit report shows that.
The signal-to-noise problem is solved by tuning thresholds, not by
filtering output. Tuning a threshold from "3 REGRESSED" to
"5 REGRESSED" because 3 keeps showing up is not loop health — it's
moving the goalposts.

**Anti-pattern 3: Audit becomes the canonical reflection.** Audit
catches *one specific class* of loop leakage. It does not replace
full reflection's evidence-block analysis, completeness check,
isolation-read discipline, or anchor verification. Running audit
instead of `/reflect:full` is a substitution that loses signal in
exchange for token savings.

**Anti-pattern 4: Audit is a perfectionist gate.** Some leakage is
expected. A rule that REGRESSED twice is not a crisis. Two stale CF
items are not unmanageable debt. Audit's value is making the
*pattern* visible, not enforcing zero-leakage. Set thresholds that
reflect "intervention is warranted," not "the system is failing."

---

## Integration with Other Sub-Commands

### `/reflect:full`

Audit informs full reflection's scope. If audit flags a high-REGRESSED
rule, the next full reflection's Applied Lessons section can name
the rule explicitly and note the audit-driven escalation. The
reflection then captures the escalation outcome (rule rewritten?
moved to memory? superseded?), which audit will see in its next pass.

### `/reflect:grow`

Audit's "orphaned wishlist entries" grep makes grow's failure mode
visible — entries captured but never swept. Without audit, this
failure mode is silent.

### `/reflect:verify`

Verify and audit are paired but distinct. Verify checks structural
integrity (Checks 1-17): does every phase entry have an INDEX row?
Do source pointers resolve? Are formats consistent? Audit checks
behavioral integrity: is the system producing the *outcomes* the
structure was designed for?

A project can pass all 17 verify checks while audit shows the loop
is leaking — verify says the machinery is intact; audit says the
machinery isn't being used. Both are needed.

### `/reflect:lookup`

Audit's REGRESSED grep is the data signal that lookup discipline is
failing. If the same rules keep being looked up *and* keep regressing,
the issue may not be lookup — it may be the rule's `**When:**` line
not matching real contexts. Audit-driven rule rewrites use lookup
to validate whether the new rule is more findable.

---

## When This Workflow Is Wrong

Three scenarios where `/reflect:audit` is not warranted:

**1. Brand-new project with no phase history.** Audit needs data to
diagnose. A project with one or two phase files has no trend signal;
audit will produce a near-empty report. Run `/reflect:audit` after
the project has 5+ phases.

**2. Reflection-heavy projects where the next full reflection is
imminent.** If `/reflect:full` is about to run, the trend signals
will be addressed in scope. Running audit immediately before is
duplicative.

**3. The author is mid-task and notices the loop seems off.** This
is actually a prompt for `/reflect:grow` (capture the suspicion as
a meta-question) or `/reflect:full` (investigate as part of
reflection), not for audit. Audit is a scheduled-or-triggered
diagnostic, not an in-the-moment thinking aid.

---

## Change Control

Changes to `/reflect:audit`:

- **Adjusting the four greps** (different commands, additional output
  fields): No version bump if semantic intent is unchanged. Record as
  drift-formalization in skill_dev_log.md.
- **Adding or removing a grep** (e.g., adding a fifth grep for some
  newly-noticed leakage class): Skill version bump. The four-grep
  contract is part of audit's promise.
- **Changing the action thresholds** (3 REGRESSED, 3 phases stale,
  etc.): No version bump; these are heuristics. Record in
  skill_dev_log.md when changed.
- **Adding rule-specific mode features** (new fields in the deep-dive
  output): No version bump. The mode itself is documented but not
  contractual.
- **Changing the report format** (column shape, summary structure):
  Skill version bump if downstream tools parse the report.

### Signals the audit is working

Track across audit runs to validate that audit is providing real
value rather than ceremony:

- **Action rate after audit:** % of audit-flagged items that result
  in concrete intervention (rule rewrite, CF closure, wishlist
  sweep, supersession) within 2 phases. Target: ≥60%. Lower
  suggests audit is producing noise rather than actionable signal.
- **Repeat-flag rate:** % of items flagged in two consecutive audit
  runs (no intervention occurred between). Target: <30%.
  Higher suggests interventions are being deferred or the threshold
  is too sensitive.
- **Surprise rate:** % of audit findings the author hadn't already
  noticed. High surprise rate (50%+) suggests audit is providing
  visibility the author lacks. Low surprise rate (10%-) suggests
  audit is confirming what's already known — still useful as
  documentation, but the value is bookkeeping rather than discovery.

These signals feed the next skill-development reflection's
evaluation of whether `/reflect:audit` is earning its place.
