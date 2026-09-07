package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class HashesTest {
  @Test
  void sha256_is_stable_and_hex() {
    assertThat(Hashes.sha256Hex("abc"))
        .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assertThat(Hashes.sha256Hex(null)).isEqualTo(Hashes.sha256Hex(""));
  }
}
