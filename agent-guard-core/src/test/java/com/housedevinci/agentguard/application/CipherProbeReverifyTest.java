package com.housedevinci.agentguard.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.domain.ArgumentCanonicalizer;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.ErrorCodes;
import com.housedevinci.agentguard.domain.Hashes;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * the security review re-verification of {@code 6f026ff} (the C1–C12 round). Every probe here asserts the
 * behaviour as it is today, i.e. the vulnerable one: engineering flips the assertion when the fix lands.
 */
class CipherProbeReverifyTest {

  /**
   * V1 (MEDIUM, C4 residual). The size cap was placed at the top of {@code gate} and {@code
   * dispatch}, but {@code ToolGuard.guarded} audits — and therefore canonicalises and parses — the
   * arguments on the two paths that run <em>before</em> either of them: the unregistered-tool
   * denial and the policy denial. Both are reachable by any caller with no role and no policy at
   * all, so the cheapest path to the guard is also the one that parses unbounded model-supplied
   * text into a {@code JsonNode} tree. C4 is not closed until every parse is behind the cap.
   *
   * <p>Fix: hoist {@code rejectIfTooLarge} into {@code guarded}, before {@code policies.resolve},
   * and let {@code gate}/{@code dispatch} keep their (now redundant) check or drop it. The two
   * denial audits then go through {@code AuditRecorder.recordOversized} like the gate path.
   */
  @Test
  void probe_the_denial_paths_parse_arguments_of_any_size() {
    var f = new GuardFixture();
    f.options = new GuardOptions(20, 32, Duration.ofHours(1), false); // 32-byte cap
    f.build();
    // whitespace makes the canonical form differ from the raw text, so the hash says which one ran
    String oversized = "{ \"a\" : \"" + "x".repeat(4096) + "\" }";
    assertThat(oversized.getBytes(StandardCharsets.UTF_8).length).isGreaterThan(32);

    var unregistered =
        f.guard.execute(
            ToolInvocation.of(GuardFixture.AGENT, "no-policy", oversized),
            Optional.empty(),
            i -> "never");

    // V1 fixed: the raw byte cap runs before the unregistered-tool lookup, so an oversized call
    // to an unregistered tool is refused as oversized, not as unregistered.
    assertThat(unregistered).isInstanceOf(GuardResult.Denied.class);
    assertThat(((GuardResult.Denied) unregistered).code())
        .isEqualTo(ErrorCodes.APPROVAL_ARGS_TOO_LARGE);
    var row = f.auditSink.latest(null, 1).get(0);
    // the payload was never parsed: the audit row carries the raw hash, not the canonical one
    assertThat(row.argsHash()).isNotEqualTo(ArgumentCanonicalizer.hash(oversized));
    assertThat(row.argsHash()).isNotEqualTo(Hashes.sha256Hex(oversized)); // V3: domain-separated

    // same on the policy-denial path: the caller has no matching role, but the cap still runs first
    f.registry.register(
        "write", new PolicyRule(Set.of("NOBODY"), Set.of(), Set.of(), SideEffect.WRITE));
    var denied =
        f.guard.execute(
            ToolInvocation.of(GuardFixture.AGENT, "write", oversized),
            Optional.empty(),
            i -> "never");

    assertThat(denied).isInstanceOf(GuardResult.Denied.class);
    assertThat(((GuardResult.Denied) denied).code()).isEqualTo(ErrorCodes.APPROVAL_ARGS_TOO_LARGE);
    assertThat(f.auditSink.latest(null, 1).get(0).argsHash())
        .isNotEqualTo(ArgumentCanonicalizer.hash(oversized));
  }

  /**
   * V2 (MEDIUM, new in C6). {@code AuditChainVerifier.chainFor} picks the hash function from the
   * row's own {@code chain_version} column. That column is part of the row an attacker rewrites,
   * and it is <em>not</em> covered by the keyed HMAC for the version it claims: marking a rewritten
   * row {@code ag1} makes the verifier recompute it with plain SHA-256, which needs no key. The
   * keyed chain exists precisely for the residual the schema documents ("a role that owns the table
   * can DISABLE TRIGGER"), and per-row version trust hands that residual back — the whole trail can
   * be rewritten and still verify INTACT.
   *
   * <p>Fix: the version may only move forward. Track the highest version seen while walking; once a
   * {@code KEYED_VERSION} row has verified, a later {@code CANONICAL_VERSION} row is BROKEN, not
   * unkeyed-verified. The migration case C6 was about (an unkeyed prefix, then keyed rows) still
   * verifies, and rewriting the prefix still breaks the first keyed row's {@code prevHash}, which
   * is under the HMAC. Test: {@code
   * CipherProbeReverifyTest.probe_a_keyed_trail_verifies_after_it_is_ rewritten_as_unkeyed}.
   *
   * <p><b>Scope note (see QUESTIONS.md V2):</b> the version-monotonicity fix detects a
   * <em>partial</em> downgrade — some rows genuinely keyed, a later row (or the whole tail)
   * downgraded to {@code ag1} — because a {@code KEYED_VERSION} row was observed first. It cannot
   * detect a downgrade of <em>every</em> row back to GENESIS: that trail is byte-for-byte what
   * {@code CipherProbeCleanGuardTest
   * .enabling_the_audit_hmac_secret_does_not_break_the_existing_trail} requires to stay INTACT (a
   * deployment that has never used HMAC, verified after a key is configured). No purely
   * row-embedded version scheme can tell those two apart; it is the same table-owner residual
   * already documented as the security review R4. This probe therefore rewrites the trail's <em>tail</em>, not
   * its head, so it exercises the case the fix actually closes.
   */
  @Test
  void probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed() {
    var key = new byte[32];
    Arrays.fill(key, (byte) 7);
    var sink = new InMemoryAuditSink(AuditChain.keyed(key));
    var recorder = new AuditRecorder(sink, Clock.systemUTC());
    var principal = new Principal("agent-1", Set.of("AGENT"), Set.of(), "acme");
    recorder.record(
        principal, "refund", "{\"amount\":1}", null, 0, AuditDecision.ALLOWED, "c1", null);
    recorder.record(
        principal, "refund", "{\"amount\":2}", null, 0, AuditDecision.ALLOWED, "c2", null);
    assertThat(AuditChainVerifier.of(sink, AuditChain.keyed(key)).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);

    // an attacker with write access to the table and no key leaves the genuinely keyed head alone
    // (rewriting it would break its own hash) and rewrites the tail, relinking with plain SHA-256
    // and stamping chain_version='ag1'
    var rows = sink.readAfter(0, 100);
    String prev = rows.get(0).hash();
    for (int i = 1; i < rows.size(); i++) {
      var forged = AuditChain.unkeyed().linkEvent(rows.get(i).withTool("read-only"), prev);
      sink.tamper(i, forged);
      prev = forged.hash();
    }

    var report = AuditChainVerifier.of(sink, AuditChain.keyed(key)).verify();

    // V2 fixed: chain_version may only move forward. Once the genuine keyed head has verified, the
    // downgraded row is BROKEN at its own sequence, not silently re-verified with plain SHA-256.
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.BROKEN);
    assertThat(report.verified()).isEqualTo(1L);
    assertThat(report.brokenAtSequence()).isEqualTo(2L);
  }

  /**
   * V3 (LOW, new in C4/C12). The oversized-rejection row hashes the raw text while every other row
   * hashes {@code ArgumentCanonicalizer.canonical(...)}, and both go into the same {@code
   * args_hash} column with no domain separation. Canonicalisation is not size-preserving — an
   * unpaired surrogate is one UTF-8 byte raw ({@code ?}) and six after the C1 escape — so a payload
   * comfortably under the cap has a canonical form well over it, and that canonical form, replayed
   * as raw text, is rejected as oversized with exactly the same {@code args_hash}. An investigator
   * joining rows by {@code args_hash} sees an allowed call and a denied one as the same arguments.
   *
   * <p>Fix: domain-separate the two hashes — {@code Hashes.sha256Hex("raw:" + argumentsJson)} in
   * {@code AuditRecorder.recordOversized} against {@code sha256Hex("canon:" + canonical)} in {@code
   * ArgumentCanonicalizer.hash} (or a distinct column value); optionally cap the canonical form as
   * well, since the 6x expansion means the cap does not bound what the guard hashes.
   */
  @Test
  void probe_an_oversized_denial_shares_an_args_hash_with_an_allowed_call() {
    int cap = 64 * 1024;
    String underTheCap = "{\"a\":\"" + "\uD800".repeat(20_000) + "\"}";
    assertThat(underTheCap.getBytes(StandardCharsets.UTF_8).length).isLessThan(cap);

    String canonical = ArgumentCanonicalizer.canonical(underTheCap);
    // the C1 escape expands each unpaired surrogate from one byte to six: the canonical form of a
    // payload the cap accepted is itself over the cap
    assertThat(canonical.getBytes(StandardCharsets.UTF_8).length).isGreaterThan(cap);

    // V3 fixed: the raw and canonical hashes are domain-separated, so an oversized denial can never
    // share args_hash with an allowed call even when the raw and canonical text coincide.
    assertThat(Hashes.sha256Hex(canonical)).isNotEqualTo(ArgumentCanonicalizer.hash(underTheCap));
  }
}
