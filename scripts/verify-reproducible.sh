#!/usr/bin/env bash
#
# Proves the build is reproducible: the same source tree, built twice, produces
# byte-identical jars for the two published artifacts.
#
#   scripts/verify-reproducible.sh
#
# How it works. Both builds are run with -Dproject.build.outputTimestamp set to the
# committer date of HEAD, so every zip entry carries that instant instead of "now".
# The jars from the first build are copied aside, the tree is rebuilt from clean, and
# the SHA-256 of each jar is compared. Tests are skipped: they do not contribute a byte
# to the jar and they cost a minute.
#
# Checked (must match):
#   agent-guard-core-<v>.jar
#   agent-guard-core-<v>-sources.jar
#   agent-guard-spring-boot-starter-<v>.jar
#   agent-guard-spring-boot-starter-<v>-sources.jar
#
# Reported but NOT enforced: the javadoc jars. javadoc embeds the JDK build string and,
# in some JDK versions, generation-time detail that -notimestamp does not remove. Maven
# Central requires a javadoc jar; nobody diffs one. See QUESTIONS.md #24.
#
# Also writes a checksum file, "<sha256>  <filename>" per jar from build 1 (the two
# builds already matched by the time this is written, or the script has already exited
# non-zero). This is what L1 compares the actually-deployed jars against after
# `clean deploy`, so a reproducible tree is not just proved in the abstract, it is proved
# to be what got published. Written OUTSIDE target/ by default (target/*.jar is what
# `mvn clean deploy` deletes and rebuilds next, a third time, right after this script
# runs) - override with REPRODUCIBLE_SHA_FILE to put it somewhere that survives that
# clean, e.g. $RUNNER_TEMP in CI. See docs/SECURITY-REVIEW-feat-release-pipeline.md L1.
#
set -euo pipefail
cd "$(dirname "$0")/.."
SHA_FILE="${REPRODUCIBLE_SHA_FILE:-reproducible-sha256.txt}"

TS="$(scripts/git-commit-timestamp.sh)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MVN_ARGS=(-B -q -DskipTests -Dproject.build.outputTimestamp="$TS" -Prelease -Dgpg.skip=true)

echo "reproducibility check"
echo "  timestamp: $TS"
echo "  scratch:   $WORK"

collect() { # collect <dir>
  local dest="$1"
  mkdir -p "$dest"
  for jar in agent-guard-core/target/*.jar agent-guard-spring-boot-starter/target/*.jar; do
    [ -e "$jar" ] || continue
    cp "$jar" "$dest/"
  done
}

echo "  build 1 ..."
./mvnw "${MVN_ARGS[@]}" clean package
collect "$WORK/one"

echo "  build 2 ..."
./mvnw "${MVN_ARGS[@]}" clean package
collect "$WORK/two"

status=0
mkdir -p "$(dirname "$SHA_FILE")"
sha_file="$SHA_FILE"
: > "$sha_file"
printf '\n%-56s %-8s %s\n' "artifact" "verdict" "sha256 (build 1)"
for f in "$WORK/one"/*.jar; do
  name="$(basename "$f")"
  other="$WORK/two/$name"
  if [ ! -e "$other" ]; then
    printf '%-56s %-8s %s\n' "$name" "MISSING" "-"
    status=1
    continue
  fi
  a="$(shasum -a 256 "$f" | cut -d' ' -f1)"
  b="$(shasum -a 256 "$other" | cut -d' ' -f1)"
  if [ "$a" = "$b" ]; then
    printf '%-56s %-8s %s\n' "$name" "same" "$a"
    printf '%s  %s\n' "$a" "$name" >> "$sha_file"
  else
    case "$name" in
      *-javadoc.jar)
        printf '%-56s %-8s %s\n' "$name" "differs" "$a  (not enforced, see QUESTIONS #24)"
        # Recorded anyway, not-enforced marker and all: L1's post-deploy comparison needs
        # a line to look up, and it applies the same not-enforced rule for *-javadoc.jar.
        printf '%s  %s  # not enforced, see QUESTIONS #24\n' "$a" "$name" >> "$sha_file"
        ;;
      *)
        printf '%-56s %-8s %s\n' "$name" "DIFFERS" "$a vs $b"
        status=1
        ;;
    esac
  fi
done

echo
if [ "$status" -eq 0 ]; then
  echo "reproducible: every enforced artifact is byte-identical across two clean builds"
  echo "  wrote: $sha_file"
else
  echo "NOT reproducible: see DIFFERS above" >&2
fi
exit "$status"
