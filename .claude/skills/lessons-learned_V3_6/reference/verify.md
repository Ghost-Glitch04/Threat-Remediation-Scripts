# Verify — Integrity Checks for Lessons Learned

Run these checks after every full reflection (SKILL.md §4a, Step 5 — VERIFY).
Each check includes the grep/command to run and what a failure looks like.

**Check categories:**
- **Reflection checks** (1–11, 14, 15, 16): run after every full
  reflection to validate the entries just authored
- **Skill-authorship checks** (12, 13, 17): run when editing the
  skill itself, not just when running a normal reflection. These
  validate that the skill is internally consistent and matches
  real-world usage.

---

## Check 1: Every phase file entry has an INDEX.md row

Phase file entries use `### N. Title` numbering (single integer, monotonic
within the file). A few files use `### N.N Title` when entries are grouped
into `## Section N — Topic` blocks — both formats are extracted here.

```bash
# Extract entry numbers from the current phase file (both "### N. " and "### N.N ")
grep -oE "^### [0-9]+(\. |\.[0-9]+ )" lessons_learned/{current_phase_file}.md \
  | grep -oE "[0-9]+(\.[0-9]+)?"

# For each entry number N (or N.N), verify it appears in INDEX.md as a source
grep -E "\|[[:space:]]*{phase_id}(:{N})?[[:space:]]*\|" lessons_learned/INDEX.md
```

**Failure:** A phase file entry number with no INDEX.md hit means a row is
missing. Add it to the Active tier.

**Notes on numbering in real phase files:** Most phase files use
`### N. Title` with the integer N restarting at 1 and increasing
monotonically. `phase22_testing.md` is the only file using the two-level
`### N.N Title` variant (grouped into `## Section N — Topic` blocks). Some
entries are narrative sections without rules attached and do not need INDEX
rows. Only entries that represent a rule, bug, pattern, or insight need to
be indexed. This check catches entries the author meant to index but forgot.

---

## Check 2: AI file Source pointers resolve to real phase entries

**AI file source pointers use the same format as INDEX row source pointers.**
Both use `{phase_id}:{entry_number}` without `.md` or `§`. In AI files the
pointer is wrapped in italics: `*Source: phase22_testing:5*`. Multi-phase
sources use comma separation: `*Source: phase10_nuclei_template_testing:4,
phase11_nuclei_round2:2*`.

```bash
# Extract all Source pointers from AI files
grep -rh "^\*Source:" lessons_learned/ai/ | sort -u

# Canonical pattern: *Source: {phase_id}:{entry_number}*
# Example:           *Source: phase22_testing:5*
#
# For each pointer:
#   1. lessons_learned/{phase_id}.md exists
#   2. grep "^### {entry_number}" lessons_learned/{phase_id}.md matches
#      (phase file entries use "### N. Title" or "### N.N Title")
```

**Failure:** A Source pointer referencing a non-existent phase file or
entry number. Fix the pointer or remove the orphaned AI rule.

**Known drift — wpscan.md:** `lessons_learned/ai/wpscan.md` is the one
file in the repo using the alternate format
`*Source: {phase_file}.md §{section}*` (12 instances). Every other AI file
(18 files, 184 instances) uses the canonical `phase_id:N` format. Check 2
treats the `.md §` format as legacy — new rules should use `phase_id:N`.
When running this check against wpscan.md, verify pointers with the
alternate grep: `grep "^### {section}" lessons_learned/{phase_file}.md`
where `{section}` is the `N.N` value after `§`.

**Drift warning:** If this check starts flagging many files as using the
`.md §` format, the drift has spread. Record it in a "What Would Help Me
Grow" entry and decide whether to normalize the repo or re-document the
format as dual.

---

## Check 3: Every rule/bug/pattern/insight has an AI subject file entry

INDEX rows of type `rule`, `bug`, or `pattern` must also appear in an
AI subject file. Type `insight` is an exception — process observations
do not always route to an AI file.

```bash
# List all entries from the phase file with their type (from INDEX.md)
grep "{phase_id}" lessons_learned/INDEX.md

# For each entry of type rule/bug/pattern, verify it has an AI file entry
# by searching the AI directory for its Source pointer:
grep -rE "Source: {phase_id}(:{N}[^0-9]|[^a-zA-Z0-9_])" lessons_learned/ai/
```

**Failure:** An INDEX.md row of type rule/bug/pattern with no AI file hit.
Write the When/Rule entry in the appropriate AI file.

---

## Check 4: _overview.md rule counts match actual heading counts

```bash
# Count actual rule headings per AI file. Canonical format is plain
# "### Title"; wpscan.md is the one outlier using "### Rule N: Title".
# Both patterns are matched by "^### ".
#
# Non-rule H3s (Overview, See also, Companion Index, etc.) are excluded
# by skipping common section names. Adjust the exclusion set if a new
# non-rule heading appears in your repo.
for f in lessons_learned/ai/*.md; do
  [ "$(basename "$f")" = "_overview.md" ] && continue
  total=$(grep -cE "^### " "$f")
  overhead=$(grep -cE "^### (Overview|See also|See Also|Companion Index|How to use|Table of|Index)" "$f")
  superseded=$(grep -c "^\*\*Superseded by:\*\*" "$f" 2>/dev/null || true)
  superseded=${superseded:-0}
  active=$((total - overhead - superseded))
  printf "%-30s active=%d (total=%d overhead=%d superseded=%d)\n" \
    "$(basename "$f")" "$active" "$total" "$overhead" "$superseded"
done

# Compare against the counts listed in _overview.md
grep -E "^\| \[" lessons_learned/ai/_overview.md
```

**Failure:** A mismatch between the computed active count and the listed
count in _overview.md. Update _overview.md with the correct number.
Superseded rules are excluded — they no longer provide actionable recall
(see templates.md → Superseded Rules).

**Heading format note:** Canonical AI file rule heading is plain
`### Imperative Title` (17 of 18 files). `### Rule N: Title` is legacy drift
used only by `wpscan.md` (12 rules). The `^### ` grep pattern here matches
both; the subtraction of overhead headings gives the true rule count.

---

## Check 5: No duplicate rules in INDEX.md

```bash
# Step 1: Find exact duplicate descriptions.
# Extract only real data rows: starts with "|", has 5+ pipe-separated fields,
# and the description column ($3) contains letters (filters table separators
# which contain only dashes, and header rows which contain "description").
awk -F'|' '
  /^\|[^-]/ && NF>=5 {
    gsub(/^ +| +$/, "", $3)
    if ($3 ~ /[a-zA-Z]/ && $3 != "description") print $3
  }
' lessons_learned/INDEX.md | sort | uniq -d

# Step 2: Near-duplicates (manual scan) — sort descriptions and look for
# adjacent entries addressing the same failure mode or concept
awk -F'|' '
  /^\|[^-]/ && NF>=5 {
    gsub(/^ +| +$/, "", $3)
    if ($3 ~ /[a-zA-Z]/ && $3 != "description") print $3
  }
' lessons_learned/INDEX.md | sort
```

**Failure:** Two rows with identical or near-identical descriptions.
Merge them — keep the one with the broader source pointer (e.g.,
`phase03_auth:2, phase07_api:4`). Step 1 catches exact matches; Step 2
requires scanning the sorted output for entries that describe the same
concept in different words.

---

## Check 6: Cross-references resolve to real AI file rules

```bash
# Extract all See Also references
grep -rn "^- See:" lessons_learned/ai/

# For each, verify the target file and rule title exist. The rule heading
# in the target file is either "### {Title}" (canonical) or
# "### Rule N: {Title}" (wpscan.md legacy). Use a pattern that accepts both:
#   grep -E "^### (Rule [0-9]+: *)?{Rule Title}" lessons_learned/ai/{file}.md
```

**Failure:** A See Also reference pointing to a non-existent file or rule
title. Update the reference or remove it.

---

## Check 6b: Companion links resolve and are mutual

```bash
# Extract all Companion references from AI files
grep -rn "^\*\*Companions:\*\*" lessons_learned/ai/

# For each companion target (file.md → "Rule Title"):
# 1. Verify the target file exists
# 2. Verify the rule heading exists (canonical or wpscan.md legacy):
#      grep -E "^### (Rule [0-9]+: *)?{Rule Title}" lessons_learned/ai/{file}.md
# 3. Verify the target rule links back (mutual):
#      grep -A 20 "{Rule Title}" lessons_learned/ai/{file}.md | grep Companions
```

**Failure modes:**
- Target file or heading doesn't exist → fix the companion reference
- Link is one-directional → add the reciprocal companion to the target rule

---

## Check 7: No orphaned carry-forward items

```bash
# Find all open CF items across all phase files
# CF items live in a table, not as line prefixes, so search the Carry-Forward
# section of each phase file.
for f in lessons_learned/phase*.md; do
  sed -n '/^## Carry-Forward/,/^## /p' "$f" | grep "^| CF-" | grep -v RESOLVED
done
```

**Failure:** An unresolved CF item in an older phase file that has no
matching `RESOLVED` or re-listing in any subsequent phase file. Carry it
forward to the current phase.

---

## Check 8: _overview.md keywords cover AI file content

```bash
# For each AI file, extract its rule headings and compare to _overview keywords
for f in lessons_learned/ai/*.md; do
  [ "$(basename "$f")" = "_overview.md" ] && continue
  echo "=== $(basename "$f") ==="
  grep "^### Rule" "$f" | head -5
done

# Scan _overview.md to verify keywords match the rule topics
cat lessons_learned/ai/_overview.md
```

**Failure:** An AI file's rules cover a topic not represented in the
_overview.md Covers column. Add the missing keyword — this is what the
lookup protocol uses to route grep queries to the right file.

---

## Check 9: AI files are not oversized

```bash
# Count rules per AI file — flag any with 30+.
# Counts all "### " headings (both canonical plain titles and legacy
# "Rule N:" format), subtracting common non-rule headings.
for f in lessons_learned/ai/*.md; do
  [ "$(basename "$f")" = "_overview.md" ] && continue
  total=$(grep -cE "^### " "$f")
  overhead=$(grep -cE "^### (Overview|See also|See Also|Companion Index|How to use|Table of|Index)" "$f")
  count=$((total - overhead))
  [ "$count" -ge 30 ] && echo "SPLIT CANDIDATE: $(basename "$f") has $count rules"
done
```

**Failure:** An AI file with 30+ rules is too large for efficient lookup.
Split it by subtopic (e.g., `testing.md` → `unit-testing.md` + `e2e-testing.md`).
Update all source pointers in the split files, `_overview.md`, and INDEX.md
Quick Reference.

---

## Check 10: Superseded rules have valid forward pointers

```bash
# Find all superseded rules in AI files
grep -rn "^\*\*Superseded by:\*\*" lessons_learned/ai/

# For each forward pointer (file.md → "New Rule Title"):
# Verify the target rule heading exists (canonical or wpscan.md legacy):
#   grep -E "^### (Rule [0-9]+: *)?{New Rule Title}" lessons_learned/ai/{file}.md

# Find superseded rows in INDEX.md
grep "\[SUPERSEDED\]" lessons_learned/INDEX.md
```

**Failure modes:**
- Forward pointer targets a non-existent rule → fix the pointer
- INDEX.md row is marked `[SUPERSEDED]` but the AI file rule isn't →
  add `**Superseded by:**` to the AI file rule
- AI file rule is superseded but INDEX.md row isn't marked → add
  `[SUPERSEDED]` prefix to the INDEX.md description
- Superseded rule still has companion links → remove or redirect companions
  to the replacement rule
- **Supersession reason missing** → every `**Superseded by:**` must also
  have a `**Supersession reason:**` line with one of:
  `corrected | refined | narrowed | split` (see templates.md).

This check was previously Check 11 in V3_3. The old Check 10 (concern maps)
was removed in V3_4 because concern maps had zero usage across 19 AI files.

---

## Check 11: AI rule isolation-read

**New in V3_4.** After writing a new AI rule, re-read only its When, optional
Not when, and Rule lines. If those three lines don't carry the rule without
the code block or Why explanation, the rule will be useless to a future
session that grep-hits only the heading. This is a discipline check, not a
batch grep sweep — it runs during authorship, not during a nightly pass.

```bash
# During authorship, extract just the isolation-read lines for a specific rule.
# Use the rule's heading text (or "Rule N:" prefix for wpscan.md):
sed -n '/^### Always use --detection-mode passive/,/^---/p' lessons_learned/ai/wpscan.md \
  | grep -E "^\*\*(When|Not when|Rule):\*\*"
```

Read the output. Does it stand alone? If a future session finds only those
three lines via grep, do they know what to do? If not, rewrite the rule.

**Failure:** The When/Rule pair cannot stand alone. Rewrite the rule so that
the three-line skeleton is self-contained.

---

## Check 12: Reference pointer resolution (skill-authorship check)

**New in V3_4.** This check validates the skill's own reference files — it
exists because the V3_3 skill shipped with two `reference/*.md` files that
were byte-for-byte duplicates of other files, breaking 11 load-bearing
pointers from SKILL.md. This check catches that failure mode at authorship
time.

```bash
# List all reference pointers in SKILL.md
grep -oE "reference/[a-z_]+\.md" .claude/skills/lessons-learned_V*/SKILL.md \
  | sort -u

# For each pointer:
# 1. Confirm the target file exists
# 2. Confirm the target file is NOT a byte-for-byte duplicate of SKILL.md
#    or of another reference file
# 3. Confirm the target file contains the section SKILL.md claims it contains
#    (e.g., if SKILL.md says "see templates.md → 'Applied Lessons Format'",
#     grep for "Applied Lessons" in templates.md and confirm it matches)

# Duplicate detection:
md5sum .claude/skills/lessons-learned_V*/SKILL.md \
       .claude/skills/lessons-learned_V*/reference/*.md \
  | sort
# All hashes should be distinct. Any two files sharing a hash is a failure.
```

**Failure modes:**
- Pointer references a file that doesn't exist → create the file or fix
  the pointer
- Target file is a byte-for-byte duplicate of another file → the author
  meant to create content and copied by mistake. Recreate the file with
  real content.
- Target file exists but doesn't contain the claimed section → either the
  SKILL.md pointer is wrong or the target file is incomplete. Fix whichever
  is out of sync.

**This check must pass before shipping a new version of this skill.** The
V3_3 failure was preventable with one `md5sum` run at authorship time.

---

## Check 13: Format drift (skill-authorship check)

**New in V3_4.** This check validates that the formats SKILL.md and
templates.md document still match what real phase files and AI files
actually write. Run it when editing the skill and when reflecting on a
phase that felt like it needed a format the skill didn't document.

```bash
# For each format element the skill documents, spot-check a sample of real
# files to confirm the documented format matches observed usage.

# Example 1: AI rule heading format.
# Canonical is plain "### Imperative Title" (17 of 18 files).
# wpscan.md uses "### Rule N: Title" (legacy, excluded).
# Flag any non-wpscan file that has adopted the "Rule N:" prefix — that's drift.
for f in lessons_learned/ai/*.md; do
  [ "$(basename "$f")" = "_overview.md" ] && continue
  [ "$(basename "$f")" = "wpscan.md" ] && continue   # known legacy
  numbered=$(grep -cE "^### Rule [0-9]+:" "$f")
  if [ "$numbered" -gt 0 ]; then
    echo "DRIFT: $(basename "$f") has $numbered rules using '### Rule N:' format (canonical is plain '### Title')"
  fi
done

# Example 2: AI file Source pointer format — dominant family is phase_id:N
# with several organic variants documented in templates.md. This check
# flags pointers that DON'T match any documented form. wpscan.md uses the
# alternate ".md §" format (12 instances, 1 file) — excluded as known legacy.
#
# Documented forms (see templates.md → Source format):
#   phase_id
#   phase_id:<id>                        where <id> is alphanumeric (incl. "-")
#   phase_id:<id>(,<id>)*                comma-separated entries
#   phase_id:<id>-<id>                   entry range
#   phase_id (multi-phase, phase_id)     multi-phase list
#   any of the above followed by " (parenthetical note)"
#
# The regex below is intentionally permissive enough to cover all documented
# forms. Hits reported by this check are real drift — genuinely undocumented
# formats that either need to be normalized or added to templates.md.

# Pattern pieces (case-insensitive — real IDs include "A1", "B", etc.):
#   phase         = [a-zA-Z0-9_]+
#   id            = [a-zA-Z0-9_-]+
#   range         = id(-id)?                 (single id or range)
#   first_entry   = :range                   (first entry in a phase — colon prefix)
#   extra_entry   = range                    (subsequent entries in same phase — no colon)
#   entries       = first_entry(,[[:space:]]*extra_entry)*
#   pointer       = phase(entries)?
#   multi         = pointer(,[[:space:]]*pointer)*
#   paren         = [[:space:]]\([^)]+\)     (optional trailing note)
#
# Full pattern assembled:
PH='[a-zA-Z0-9_]+'
ID='[a-zA-Z0-9_-]+'
RANGE="${ID}(-${ID})?"
ENTRIES=":${RANGE}(,[[:space:]]*${RANGE})*"
PTR="${PH}(${ENTRIES})?"
MULTI="${PTR}(,[[:space:]]*${PTR})*"
PAREN="([[:space:]]\\([^)]+\\))?"
FULL="^\\*Source: ${MULTI}${PAREN}\\*$"

for f in lessons_learned/ai/*.md; do
  [ "$(basename "$f")" = "_overview.md" ] && continue
  [ "$(basename "$f")" = "wpscan.md" ] && continue   # known legacy format
  total=$(grep -c "^\*Source:" "$f")
  matching=$(grep -cE "$FULL" "$f")
  if [ "$total" -gt 0 ] && [ "$matching" -lt "$total" ]; then
    echo "DRIFT: $(basename "$f") has $total Source lines but only $matching match documented forms"
  fi
done

# Example 3: INDEX row source-pointer format.
# Skill says "{phase_id}:{N}" — N is an integer (entry number or line number).
# Accepts: phase_id, phase_id:N, phase_id:N.N, phase_id:N,M, phase_id:N-M.
#
# Only inspect rows inside "## Active Index" / "## Foundation Index" /
# "## Reference Index" sections — the top-of-file "AI Subject Files" table
# has a different 3-column shape and would produce false positives.
awk -F'|' '
  /^## (Active|Foundation|Reference) Index/ { inside=1; next }
  /^## / { inside=0 }
  inside && /^\|[^-]/ && NF==6 {
    gsub(/^ +| +$/, "", $4)
    if ($4 ~ /[a-zA-Z0-9]/ && $4 != "source") print $4
  }
' lessons_learned/INDEX.md \
  | grep -vE "^[a-z0-9_]+(:[a-zA-Z0-9_-]+([,-][a-zA-Z0-9_-]+)*(\.[0-9]+)?)?( *, *[a-z0-9_]+(:[a-zA-Z0-9_-]+([,-][a-zA-Z0-9_-]+)*(\.[0-9]+)?)?)*( \([^)]+\))?$" \
  | head -20
# Any output = rows whose source pointers don't match the documented format.
```

**Failure modes:**
- Real files use a format the skill doesn't document → update
  templates.md to document the real format, or update the real files to
  match (whichever makes more sense for the divergence).
- Skill documents a format that has zero real-world usage → the feature
  is either dead (delete from skill) or unused-but-useful (keep documented,
  add a worked example).

**Relation to Check 12:** Check 12 validates that the skill's reference
pointers resolve. Check 13 validates that the skill's documented formats
match the repo's actual formats. Check 12 catches authoring mistakes
(pointers that point nowhere). Check 13 catches drift (the skill and the
repo grew apart over time).

---

## Check 14: Anchor consistency on Bugs and Design Decisions

**New in V3.6.** Validates INV-PHASE-02 — every actionable entry in
Bugs/Pitfalls and Design Decisions sections carries a `**Lesson:**`
line containing at least one citation pattern (see `evidence.md`
§"Citation patterns").

```bash
# For each phase file, walk Bugs / Design Decisions / What Went Badly
# sections. For each `### N. Title` heading, the next 30 lines must
# contain a `**Lesson:**` line with at least one citation pattern.

# Citation patterns (combined regex — match any one):
#   commit SHA       commit [a-f0-9]{7,}
#   file:line        \.[a-z]+:[0-9]+
#   function call    [a-zA-Z_][a-zA-Z0-9_]*\(\)
#   specific count   [0-9]+ (files|rows|lines|seconds|requests|tests|attempts|...)
#   command flag     --[a-z][a-z0-9-]*
#   test name        test_[a-zA-Z_]
#   error class      [A-Z][a-zA-Z]+(Error|Exception)

CITATION_RE='commit [a-f0-9]{7,}|\.[a-z]+:[0-9]+|[a-zA-Z_][a-zA-Z0-9_]*\(\)|[0-9]+ (files|rows|lines|seconds|requests|tests|attempts|methods|functions|columns|tables|MB|KB|GB|chars|bytes)|--[a-z][a-z0-9-]*|test_[a-zA-Z_]|[A-Z][a-zA-Z]+(Error|Exception)'

for f in lessons_learned/phase*.md; do
  awk -v file="$f" -v cite="$CITATION_RE" '
    BEGIN { in_section=0; entry_line=0 }
    /^## (Bugs|Pitfalls|Design Decisions|What Went Badly)/ {
      flush()
      in_section=1; next
    }
    /^## / {
      flush()
      in_section=0; next
    }
    in_section && /^### [0-9]+/ {
      flush()
      entry=$0; entry_line=NR; have_anchor=0; have_citation=0
    }
    in_section && /^\*\*Lesson:\*\*/ && entry_line>0 && NR-entry_line<=30 {
      have_anchor=1
      if ($0 ~ cite) have_citation=1
    }
    END { flush() }
    function flush() {
      if (entry_line==0) return
      if (!have_anchor)
        printf "%s: MISSING anchor on entry: %s (line %d)\n", file, entry, entry_line
      else if (!have_citation)
        printf "%s: ANCHOR has no citation pattern: %s (line %d)\n", file, entry, entry_line
      entry_line=0
    }
  ' "$f"
done
```

**Failure modes:**
- Entry has no `**Lesson:**` line within 30 lines of its heading →
  add one with at least one specific citation
- `**Lesson:**` line exists but contains no citation pattern → rewrite
  per `evidence.md` §"Citation patterns"

Check 14 catches *format-level* violations of the anchor discipline.
Content-level violations (anchor exists with citation but is vague,
narrative, or non-prescriptive) require human judgment — see
`evidence.md` §"Anti-patterns".

**Variant exemptions:**
- Meta-reflection variant — Summary Judgment prose section is not
  indexed and is exempt
- Case-study variant — descriptive teaching sections are exempt;
  only entries in "Generalized Lessons" (or equivalent indexed
  section) are checked

These exemptions are detected by Check 16's variant routing — Check
14 should be run after Check 16 so variant routing is established.

---

## Check 15: Meta-note sub-type coverage

**New in V3.6.** Validates that every wishlist entry — both phase-file
"What Would Help Me Grow" sections and standalone `wishlist.md`
entries — declares one of the three sub-types from INV-WISHLIST-02:
`meta-fix`, `meta-question`, `meta-wish`.

```bash
# Phase-file wishlist entries
for f in lessons_learned/phase*.md; do
  awk -v file="$f" '
    /^## (What Would Help Me Grow|Tooling Wishlist)/ { in_section=1; next }
    /^## / { in_section=0 }
    in_section && /^### / {
      check()
      entry=$0; entry_line=NR; have_subtype=0
    }
    in_section && /(meta-fix|meta-question|meta-wish)/ &&
                  entry_line>0 && NR-entry_line<=10 { have_subtype=1 }
    END { check() }
    function check() {
      if (entry_line==0) return
      if (!have_subtype)
        printf "%s: MISSING sub-type on wishlist entry: %s (line %d)\n", file, entry, entry_line
      entry_line=0
    }
  ' "$f"
done

# Standalone wishlist.md
if [ -f lessons_learned/meta/wishlist.md ]; then
  awk -F'|' -v file="lessons_learned/meta/wishlist.md" '
    /^\| TW-W-/ {
      gsub(/^ +| +$/, "", $3)
      gsub(/^ +| +$/, "", $2)
      if ($3 != "meta-fix" && $3 != "meta-question" && $3 != "meta-wish") {
        printf "%s: invalid or missing sub-type on %s: \"%s\"\n", file, $2, $3
      }
    }
  ' lessons_learned/meta/wishlist.md
fi
```

**Failure modes:**
- Wishlist entry has no sub-type → add one (default to
  `meta-question` if uncertain — see `meta_classification.md`
  §"Edge case 2")
- Sub-type value is malformed (typo, wrong format) → fix to match
  the vocabulary
- Standalone wishlist row has empty Sub-type column → either populate
  or remove the row

Legacy V3.4 entries with bare `type: meta` are grandfathered and
not flagged.

---

## Check 16: Variant conformance

**New in V3.6.** Validates INV-PHASE-08 — every phase file declares a
`**Format:**` variant, and the variant's required sections are present
per `templates.md` §"Phase File Variants".

```bash
for f in lessons_learned/phase*.md; do
  variant=$(head -15 "$f" | grep "^\*\*Format:\*\*" | head -1 \
            | sed 's/^\*\*Format:\*\* *//' | sed 's/[[:space:]]*$//')

  if [ -z "$variant" ]; then
    echo "$f: MISSING **Format:** declaration (INV-PHASE-08)"
    continue
  fi

  case "$variant" in
    canonical)
      grep -q "^## Overview" "$f" \
        || echo "$f: canonical variant MISSING Overview"
      grep -qE "^## (Applied Lessons|Missed)" "$f" \
        || echo "$f: canonical variant MISSING Applied Lessons section"
      ;;
    meta-reflection)
      grep -q "^## Overview" "$f" \
        || echo "$f: meta-reflection variant MISSING Overview"
      grep -q "^## Summary Judgment" "$f" \
        || echo "$f: meta-reflection variant MISSING Summary Judgment"
      grep -q "^## Phase Inventory" "$f" \
        || echo "$f: meta-reflection variant MISSING Phase Inventory"
      ;;
    case-study)
      grep -q "^## Overview" "$f" \
        || echo "$f: case-study variant MISSING Overview"
      ;;
    *)
      # Drift Intake — proposed variant flagged as warning, not failure
      echo "$f: DRIFT WARNING — proposed variant '$variant' (Drift Intake Protocol applies)"
      ;;
  esac
done
```

**Failure modes:**
- Missing `**Format:**` declaration → add line per INV-PHASE-08.
  Retroactive bootstrap: existing phase files without this line are
  assumed `Format: canonical` until edited.
- Required section missing for declared variant → add the section,
  OR change the variant if the file's actual shape differs from the
  declared variant
- Unknown variant → either align to a documented variant
  (`templates.md` §"Phase File Variants"), or run the Drift Intake
  Protocol (`reference/drift_intake.md`) to formalize the new variant

Drift-flagged variants are *warnings*, not failures. Drift Intake is
the formal route for variant evolution; until a proposed variant has
recurred 3+ times and graduated, this check reports it but does not
fail.

---

## Check 17: Sub-command contract (skill-authorship check)

**New in V3.6.** Validates INV-SUBCMD-01 — every `/reflect:*`
sub-command referenced in SKILL.md prose has a corresponding spec
row in §"Per-Sub-Command Specs", with allowed-tools, pre-load list,
and write list documented.

```bash
SKILL_FILE=$(ls .claude/skills/lessons-learned_V*/SKILL.md 2>/dev/null | head -1)

if [ -z "$SKILL_FILE" ]; then
  echo "Check 17: SKILL.md not found at expected path"
  exit 1
fi

# Extract all sub-command names referenced in SKILL.md
referenced=$(grep -oE "/reflect:[a-z]+" "$SKILL_FILE" | sort -u)

# Extract sub-commands declared in the spec table (column-1 of the table
# in §"Per-Sub-Command Specs")
specced=$(sed -n '/^## .*Per-Sub-Command Specs/,/^## /p' "$SKILL_FILE" \
          | grep -oE "/reflect:[a-z]+" | sort -u)

# Each referenced sub-command should appear in the spec table
for cmd in $referenced; do
  echo "$specced" | grep -qx "$cmd" \
    || echo "Check 17: $cmd referenced in SKILL.md but missing spec row"
done

# Each specced sub-command should be referenced somewhere in workflow text
for cmd in $specced; do
  echo "$referenced" | grep -qx "$cmd" \
    || echo "Check 17: $cmd in spec table but never referenced in workflow text"
done

# Each spec row must declare allowed-tools (text "Read", "Edit", "Bash", etc.
# in the row — heuristic: the row contains at least one of these tokens)
sed -n '/^## .*Per-Sub-Command Specs/,/^## /p' "$SKILL_FILE" \
  | grep -E "^\| /reflect:" \
  | while read -r row; do
      cmd=$(echo "$row" | grep -oE "/reflect:[a-z]+")
      echo "$row" | grep -qE "(Read|Write|Edit|Bash|Grep|Glob)" \
        || echo "Check 17: $cmd spec row has no allowed-tools declaration"
    done
```

**Failure modes:**
- Sub-command referenced in workflow text but not in spec table →
  add the spec row
- Sub-command in spec table but never referenced elsewhere → either
  remove it, or document its invocation path
- Spec row has no allowed-tools declaration → add tool scoping
- Sub-command name doesn't match frontmatter `argument-hint` format →
  align them

This check catches authoring drift between SKILL.md prose and the
sub-command spec table — the same class of failure Check 12 catches
for reference pointers.

**Relation to Checks 12 and 13:** All three are skill-authorship
checks (run when editing the skill, not just reflecting). Check 12
validates pointers resolve, Check 13 validates documented formats
match real usage, Check 17 validates sub-command spec consistency.
Together they form the skill's self-integrity audit.

---

## Quick Pass (abbreviated check)

When time is limited, run Checks 1, 4, and 8 — they catch the most common
issues (missing INDEX rows, stale _overview counts, and stale _overview
keywords that degrade lookup accuracy).

**After every full reflection, also run Checks 14, 15, and 16** —
these validate the entries the reflection just authored conform to
v3.5/v3.6 invariants. Each runs in seconds.

When editing the skill itself, also run Checks 12, 13, and 17. These
are the prove-first discipline from `scripting-standards_V4_6` applied
to this skill: every format the skill documents must be grep-checkable
against real usage, every reference pointer must resolve, and every
sub-command must have a spec row before the skill ships.
