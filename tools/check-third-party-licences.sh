#!/usr/bin/env bash
#
# All-of denial pass over every generated THIRD-PARTY-NOTICES.txt, outside the
# license-maven-plugin allowlist execution (pom.xml, third-party-notices). The plugin's
# <includedLicenses> is an any-of *permission* check: a dependency passes if ANY one of its
# declared licences is on the allowlist, which is the legally correct answer for a genuinely
# dual-licensed artifact (logback: EPL-2.0 OR LGPL-2.1; jakarta.annotation-api: EPL-2.0 OR
# GPL-2.0-with-classpath-exception) but also the wrong answer for a dependency whose POM
# lists two CUMULATIVE licences, e.g. "Apache-2.0 OR GPL-3.0" declared as two licence blocks.
# The plugin has no way to tell the two cases apart; this script is the second pass that does,
# by only ever allowing the exception for a coordinate a human wrote down. See
# docs/SECURITY-REVIEW-feat-release-pipeline.md M1/M2, QUESTIONS.md #22.
#
# Never add <excludedLicenses> to the plugin execution instead of this script: it makes the
# build pass AND deletes the GPL-3.0 declaration from the notices file that ships as release
# evidence (M2). The denial pass must run outside the plugin, against the evidence the plugin
# already produced, so a rejected dependency's full licence declaration stays on record.
#
#   tools/check-third-party-licences.sh
#
# Exit 0: every dependency in every THIRD-PARTY-NOTICES.txt found under */target/ is clean.
# Exit 1: at least one dependency carries a denied licence token, named with its coordinate.
#
set -uo pipefail
cd "$(dirname "$0")/.."

# Coordinates that are known, by a human, to be genuinely dual-licensed under a permissive
# OR a copyleft term (never both applying at once). An exception is a coordinate, never a
# licence-token pattern: it names precisely which dependency the human accepted.
ALLOWED_COORDINATES=(
  "ch.qos.logback:logback-classic"
  "ch.qos.logback:logback-core"
  "jakarta.annotation:jakarta.annotation-api"
)

# Denied licence tokens (normalised, case-insensitive). Any dependency declaring ANY of
# these among its licences fails, regardless of what else it also declares.
DENIED_TOKENS=(
  gpl-1.0 gpl-2.0 gpl-3.0
  lgpl-2.0 lgpl-2.1 lgpl-3.0
  agpl-1.0 agpl-3.0
  sspl-1.0
  cddl-1.0 cddl-1.1
  mpl-1.1 mpl-2.0
  cpol
  eupl-1.2
  busl-1.1
  elastic-2.0
  cc-by-nc
)

is_allowed_coordinate() {
  local coord="$1" c
  for c in "${ALLOWED_COORDINATES[@]}"; do
    [ "$coord" = "$c" ] && return 0
  done
  return 1
}

is_denied_token() {
  local raw="$1" norm t
  norm="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  # Any token whose normalised form contains "gpl" without a classpath-exception
  # qualifier is denied outright, even if it is not one of the exact strings below
  # (catches spellings such as "GPL-2.0-only" or "GNU General Public License v3").
  # "classpath-exception", "classpath exception" and the abbreviation "cpe" (as in
  # POM-declared "GPL2 w/ CPE") are all recognised forms of the qualifier.
  if [[ "$norm" == *gpl* ]] \
    && [[ "$norm" != *classpath-exception* ]] \
    && [[ "$norm" != *classpath\ exception* ]] \
    && [[ "$norm" != *cpe* ]]; then
    return 0
  fi
  for t in "${DENIED_TOKENS[@]}"; do
    [ "$norm" = "$t" ] && return 0
  done
  return 1
}

status=0
found_any=0

while IFS= read -r -d '' notices; do
  found_any=1
  # Each dependency line looks like:
  #   (Apache-2.0) Gson (com.google.code.gson:gson:2.13.2 - https://...)
  #   (Apache-2.0) (GPL-3.0) syn-dual (cipher.synthetic:syn-dual:1.0 - no url defined)
  # perl extracts: every leading "(...)" licence token, plus the coordinate paren
  # ("group:artifact:version - url") that follows the dependency name.
  while IFS=$'\t' read -r coord tokens; do
    [ -n "$coord" ] || continue
    # Compare group:artifact only; the exception is a coordinate a human wrote down,
    # not a coordinate-plus-whatever-version-happens-to-be-on-the-classpath-today.
    ga="${coord%:*}"
    if is_allowed_coordinate "$ga"; then
      continue
    fi
    IFS='|' read -ra tok_list <<<"$tokens"
    for tok in "${tok_list[@]}"; do
      [ -n "$tok" ] || continue
      if is_denied_token "$tok"; then
        echo "check-third-party-licences: DENIED licence '$tok' on $coord (from $notices)" >&2
        status=1
      fi
    done
  done < <(perl -ne '
      if (/^\s*((?:\([^()]*\)\s*)+)\S.*?\(([\w.\-]+:[\w.\-]+:[\w.\-]+)\s*-/) {
        my ($licences, $coord) = ($1, $2);
        my @tokens;
        while ($licences =~ /\(([^()]*)\)/g) { push @tokens, $1; }
        print "$coord\t" . join("|", @tokens) . "\n";
      }
    ' "$notices")
done < <(find . -path '*/target/THIRD-PARTY-NOTICES.txt' -print0)

if [ "$found_any" -eq 0 ]; then
  echo "check-third-party-licences: no THIRD-PARTY-NOTICES.txt found under */target/ (did third-party-notices run first?)" >&2
  exit 1
fi

if [ "$status" -eq 0 ]; then
  echo "check-third-party-licences: clean"
else
  echo "check-third-party-licences: FAILED, see DENIED lines above" >&2
fi
exit "$status"
