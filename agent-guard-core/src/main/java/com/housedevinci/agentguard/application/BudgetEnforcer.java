package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.BudgetExceededException;
import com.housedevinci.agentguard.domain.BudgetKind;
import com.housedevinci.agentguard.domain.BudgetLimit;
import com.housedevinci.agentguard.domain.BudgetPolicy;
import com.housedevinci.agentguard.domain.BudgetScope;
import com.housedevinci.agentguard.domain.BudgetStore;
import com.housedevinci.agentguard.domain.BudgetSubjectMissingException;
import com.housedevinci.agentguard.domain.Principal;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Enforces {@link BudgetLimit}s <b>before dispatch</b>. Call and step counters are incremented
 * atomically and compared; token counters are checked before the call and recorded after it, once
 * the usage metadata is known. A parked call counts as a call; its later execution does not count
 * again.
 */
public final class BudgetEnforcer {

  private final List<BudgetLimit> limits;
  private final BudgetStore store;
  private final Clock clock;
  private final MissingSubjectPolicy missingSubject;

  public BudgetEnforcer(List<BudgetLimit> limits, BudgetStore store, Clock clock) {
    this(limits, store, clock, MissingSubjectPolicy.DENY);
  }

  public BudgetEnforcer(
      List<BudgetLimit> limits,
      BudgetStore store,
      Clock clock,
      MissingSubjectPolicy missingSubject) {
    this.limits = List.copyOf(Objects.requireNonNull(limits, "limits"));
    this.store = Objects.requireNonNull(store, "store");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.missingSubject = Objects.requireNonNull(missingSubject, "missingSubject");
  }

  public static BudgetEnforcer none(BudgetStore store, Clock clock) {
    return new BudgetEnforcer(List.of(), store, clock);
  }

  public List<BudgetLimit> limits() {
    return limits;
  }

  public MissingSubjectPolicy missingSubjectPolicy() {
    return missingSubject;
  }

  /**
   * Reserves one tool call / step for the invocation.
   *
   * @throws BudgetExceededException when any applicable window is exhausted
   * @throws BudgetSubjectMissingException when a scope has no subject and the policy is DENY
   */
  public void reserve(ToolInvocation invocation) {
    var now = clock.instant();
    for (BudgetLimit limit : limits) {
      Optional<String> subject = subjectOrFallback(limit, invocation);
      if (subject.isEmpty()) {
        continue;
      }
      var key = limit.key(subject.get(), now);
      var ttl = ttl(limit, now);
      switch (limit.kind()) {
        case TOOL_CALLS, STEPS -> {
          long used = store.incrementAndGet(key, 1, ttl);
          if (used > limit.limit()) {
            throw new BudgetExceededException(limit, used);
          }
        }
        case TOKENS -> {
          long used = store.current(key);
          if (BudgetPolicy.wouldExceed(limit.limit(), used, 1)) {
            throw new BudgetExceededException(limit, used);
          }
        }
      }
    }
  }

  /** Records consumed tokens after the call; never throws. */
  public void recordTokens(Principal principal, String conversationId, long tokens) {
    if (tokens <= 0) {
      return;
    }
    var now = clock.instant();
    var invocation = new ToolInvocation(principal, "-", "", conversationId, null);
    for (BudgetLimit limit : limits) {
      if (limit.kind() != BudgetKind.TOKENS) {
        continue;
      }
      subject(limit.scope(), invocation)
          .ifPresent(s -> store.incrementAndGet(limit.key(s, now), tokens, ttl(limit, now)));
    }
  }

  private Optional<String> subjectOrFallback(BudgetLimit limit, ToolInvocation invocation) {
    Optional<String> subject = subject(limit.scope(), invocation);
    if (subject.isPresent() || limit.scope() == BudgetScope.PRINCIPAL) {
      return subject;
    }
    return switch (missingSubject) {
      case DENY -> throw new BudgetSubjectMissingException(limit);
      case FALLBACK_TO_PRINCIPAL ->
          Optional.of("principal-fallback:" + invocation.principal().id());
      case SKIP -> Optional.empty();
    };
  }

  private static Optional<String> subject(BudgetScope scope, ToolInvocation invocation) {
    return switch (scope) {
      case PRINCIPAL -> Optional.of(invocation.principal().id());
      case TENANT -> invocation.principal().tenantId();
      case CONVERSATION -> Optional.ofNullable(invocation.conversationId());
    };
  }

  private static Duration ttl(BudgetLimit limit, java.time.Instant now) {
    // keep the counter a little past the window end so late readers still see it
    return Duration.between(now, limit.windowEnd(now)).plusSeconds(60);
  }
}
