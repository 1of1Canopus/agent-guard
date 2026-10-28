#!/usr/bin/env bash
#
# Starts the sample MCP server image and introspects it over stdio, the way an MCP directory
# (Glama) does before it lists and scores a server: `docker run -i`, then `initialize`,
# `notifications/initialized`, `tools/list` and one `tools/call` as newline-delimited JSON-RPC.
#
#   tools/check-sample-container.sh <image>
#
# Exit 0: the container answered `initialize` with the sample's server name, `tools/list` with
# both sample tools, and refused a `tools/call` of the write tool (no principal on stdio, so
# the tool policy denies it), inside the deadline. Exit 1 otherwise: no answer, a wrong answer, a
# non-JSON line on stdout (a log line there would corrupt the transport), or a missing argument.
# Fail closed: a check that could not run is not a check that passed.
#
# The deadline (CHECK_DEADLINE_SECONDS, default 30) covers the whole exchange, JVM start
# included. On exit the container is stopped and the answers are printed, so a CI log shows
# what the server said.
set -euo pipefail

image="${1:-}"
if [ -z "$image" ]; then
  echo "usage: $0 <image>" >&2
  exit 1
fi
deadline_seconds="${CHECK_DEADLINE_SECONDS:-30}"
case "$deadline_seconds" in
  '' | *[!0-9]*)
    echo "CHECK_DEADLINE_SECONDS must be a whole number of seconds" >&2
    exit 1
    ;;
esac

work="$(mktemp -d)"
name="agent-guard-sample-check-$$"
fifo="$work/stdin"
out="$work/stdout"
err="$work/stderr"
mkfifo "$fifo"
: >"$out"
: >"$err"

cleanup() {
  exec 3>&- 2>/dev/null || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -f "$fifo" "$out" "$err"
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

# --network none: introspection needs no network, and the check proves the image starts
# without one (no database, no download at start).
docker run -i --rm --name "$name" --network none "$image" <"$fifo" >"$out" 2>"$err" &
exec 3>"$fifo"

end=$(($(date +%s) + deadline_seconds))

# Waits until stdout holds a JSON-RPC response with the given id; fails at the deadline.
await_id() {
  local id="$1"
  while :; do
    if grep -q "\"id\":${id}[,}]" "$out"; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$end" ]; then
      echo "FAIL: no JSON-RPC response with id ${id} within ${deadline_seconds}s" >&2
      echo "--- stdout" >&2
      cat "$out" >&2
      echo "--- stderr (last 40 lines)" >&2
      tail -40 "$err" >&2
      return 1
    fi
    sleep 0.5
  done
}

printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sample-container-check","version":"1"}}}' >&3
await_id 1
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&3
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' >&3
await_id 2
# Fail closed: a stdio caller has no principal, so a write tool must be refused, never run.
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"refund_order","arguments":{"orderId":"42"}}}' >&3
await_id 3

initialize_answer="$(grep '"id":1[,}]' "$out" | head -1)"
tools_answer="$(grep '"id":2[,}]' "$out" | head -1)"
call_answer="$(grep '"id":3[,}]' "$out" | head -1)"
echo "initialize -> $initialize_answer"
echo "tools/list -> $tools_answer"
echo "tools/call refund_order -> $call_answer"

failed=0
# Every stdout line must be a JSON-RPC message: anything else breaks a real client.
if grep -v '^{"jsonrpc":"2.0"' "$out" | grep -q .; then
  echo "FAIL: stdout carries a line that is not JSON-RPC" >&2
  grep -v '^{"jsonrpc":"2.0"' "$out" | head -5 >&2
  failed=1
fi
case "$initialize_answer" in
  *'"serverInfo":{'*'"name":"agent-guard-sample"'*) ;;
  *) echo "FAIL: initialize did not name the server agent-guard-sample" >&2; failed=1 ;;
esac
for tool in get_order refund_order; do
  case "$tools_answer" in
    *"\"name\":\"$tool\""*) ;;
    *) echo "FAIL: tools/list does not list $tool" >&2; failed=1 ;;
  esac
done
case "$call_answer" in
  *'"isError":true'*) case "$call_answer" in
      *AG-POLICY-001*) ;;
      *) echo "FAIL: tools/call was refused, but not by the tool policy (AG-POLICY-001)" >&2; failed=1 ;;
    esac ;;
  *) echo "FAIL: tools/call refund_order was not refused over stdio" >&2; failed=1 ;;
esac
if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "OK: the sample container answered initialize and tools/list over stdio and refused the tool call"
