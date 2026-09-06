package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class DecisionStateTest {

  @Test
  void pending_can_move_to_each_terminal_state() {
    assertThat(DecisionState.PENDING.transitionTo(DecisionState.APPROVED)).isEqualTo(DecisionState.APPROVED);
    assertThat(DecisionState.PENDING.transitionTo(DecisionState.REJECTED)).isEqualTo(DecisionState.REJECTED);
    assertThat(DecisionState.PENDING.transitionTo(DecisionState.EXPIRED)).isEqualTo(DecisionState.EXPIRED);
  }

  static Stream<Arguments> illegal() {
    return Stream.of(
        Arguments.of(DecisionState.PENDING, DecisionState.PENDING),
        Arguments.of(DecisionState.APPROVED, DecisionState.APPROVED),
        Arguments.of(DecisionState.APPROVED, DecisionState.REJECTED),
        Arguments.of(DecisionState.APPROVED, DecisionState.EXPIRED),
        Arguments.of(DecisionState.APPROVED, DecisionState.PENDING),
        Arguments.of(DecisionState.REJECTED, DecisionState.APPROVED),
        Arguments.of(DecisionState.REJECTED, DecisionState.REJECTED),
        Arguments.of(DecisionState.REJECTED, DecisionState.EXPIRED),
        Arguments.of(DecisionState.REJECTED, DecisionState.PENDING),
        Arguments.of(DecisionState.EXPIRED, DecisionState.APPROVED),
        Arguments.of(DecisionState.EXPIRED, DecisionState.REJECTED),
        Arguments.of(DecisionState.EXPIRED, DecisionState.EXPIRED),
        Arguments.of(DecisionState.EXPIRED, DecisionState.PENDING));
  }

  @ParameterizedTest(name = "{0} -> {1} throws")
  @MethodSource("illegal")
  void every_other_transition_throws(DecisionState from, DecisionState to) {
    assertThat(from.canTransitionTo(to)).isFalse();
    assertThatThrownBy(() -> from.transitionTo(to))
        .isInstanceOf(IllegalDecisionTransitionException.class)
        .hasMessageContaining(from.name())
        .hasMessageContaining(to.name());
  }

  @Test
  void terminal_flags() {
    assertThat(DecisionState.PENDING.isTerminal()).isFalse();
    assertThat(DecisionState.APPROVED.isTerminal()).isTrue();
    assertThat(DecisionState.REJECTED.isTerminal()).isTrue();
    assertThat(DecisionState.EXPIRED.isTerminal()).isTrue();
  }
}
