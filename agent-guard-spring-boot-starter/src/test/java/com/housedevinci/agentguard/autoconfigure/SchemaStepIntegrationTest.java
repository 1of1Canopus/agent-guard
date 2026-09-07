package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * L10: the schema step runs once per DataSource, and warns when the runtime role owns the tables.
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class SchemaStepIntegrationTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  static HikariDataSource ds;

  @BeforeAll
  static void open() {
    ds = new HikariDataSource();
    ds.setJdbcUrl(POSTGRES.getJdbcUrl());
    ds.setUsername(POSTGRES.getUsername());
    ds.setPassword(POSTGRES.getPassword());
  }

  @AfterAll
  static void close() {
    ds.close();
  }

  @Test
  void schema_runs_once_per_datasource_and_warns_about_the_owner_role(CapturedOutput output) {
    var runner =
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
            // no destroy method: JdbcAuditSink's constructor now opens a connection to check the
            // trail's keyed state at startup (keyed-from-birth, QUESTIONS.md #20), so this shared
            // DataSource must survive the first context's shutdown for the second "same DataSource"
            // context below — Spring's default inferred destroy method (close/shutdown) would
            // otherwise close the pool when the first context closes.
            .withBean(DataSource.class, () -> ds, bd -> bd.setDestroyMethodName(""))
            .withPropertyValues("agentguard.enabled=true", "agentguard.audit.unkeyed=true");
    runner.run(ctx -> assertThat(ctx.getBean(AuditChainVerifier.class).verify().intact()).isTrue());
    runner.run(ctx -> assertThat(ctx).hasNotFailed()); // second context, same DataSource
    long runs =
        output.getOut().lines().filter(l -> l.contains("agentguard: schema step ran")).count();
    assertThat(runs).isEqualTo(1);
    assertThat(output).contains("runtime database role owns agentguard_audit");
  }
}
