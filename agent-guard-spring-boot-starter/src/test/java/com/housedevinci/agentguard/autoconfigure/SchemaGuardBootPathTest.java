package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.jdbc.JdbcDecisionStore;
import com.housedevinci.agentguard.adapter.jdbc.JdbcSupport;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.BudgetStore;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Every boot path of the starter reaches the audit trail guard check before a JDBC store is handed
 * out: {@code initialize-schema} true and false, owner and non-owner role, guarded, archived (the
 * 0.1.x remedy state) and 0.1.1-fresh ({@code tgenabled=O}) schemas, lazy initialization, a
 * budget-only JDBC configuration, and a schema created by {@code spring.sql.init} in the same boot.
 * A MEMORY-only context never builds the check.
 */
@Testcontainers
class SchemaGuardBootPathTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  private static final AtomicInteger SEQ = new AtomicInteger();
  private static final String RUNTIME_PASSWORD = "boot-runtime";

  private static String freshDatabase() throws SQLException {
    String db = "boot_" + SEQ.incrementAndGet();
    exec("test", "CREATE DATABASE " + db);
    exec(db, "REVOKE CREATE ON SCHEMA public FROM PUBLIC");
    return db;
  }

  private static String url(String db) {
    return "jdbc:postgresql://"
        + POSTGRES.getHost()
        + ":"
        + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
        + "/"
        + db;
  }

  private static void exec(String db, String... statements) throws SQLException {
    try (Connection c =
            DriverManager.getConnection(url(db), POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement()) {
      for (String s : statements) {
        st.execute(s);
      }
    }
  }

  private static String query(String db, String sql) throws SQLException {
    try (Connection c =
            DriverManager.getConnection(url(db), POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      rs.next();
      return rs.getString(1);
    }
  }

  private static DataSource ds(String db, String user, String password) {
    var ds = new PGSimpleDataSource();
    ds.setUrl(url(db));
    ds.setUser(user);
    ds.setPassword(password);
    return ds;
  }

  private static DataSource owner(String db) {
    return ds(db, POSTGRES.getUsername(), POSTGRES.getPassword());
  }

  private static DataSource runtime(String db) throws SQLException {
    String role = "rt_" + db;
    exec(
        db,
        "CREATE ROLE " + role + " LOGIN PASSWORD '" + RUNTIME_PASSWORD + "'",
        "GRANT SELECT, INSERT ON agentguard_audit TO " + role,
        "GRANT USAGE ON SEQUENCE agentguard_audit_seq_seq TO " + role,
        "GRANT SELECT, INSERT, UPDATE ON agentguard_decision, agentguard_audit_anchor TO " + role,
        "GRANT SELECT, INSERT, UPDATE, DELETE ON agentguard_budget TO " + role);
    return ds(db, role, RUNTIME_PASSWORD);
  }

  private static String resource(String path) {
    try (InputStream in = SchemaGuardBootPathTest.class.getResourceAsStream(path)) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The 0.1.0/0.1.1 script, byte for byte (core test resource copy). */
  private static final String RELEASED_011 =
      "/com/housedevinci/agentguard/schema-postgresql-0.1.1.sql";

  private static void applyReleased011(String db) throws SQLException {
    exec(db, "BEGIN", resource(RELEASED_011), "COMMIT");
  }

  /** The AG-AUDIT-002 remedy as 0.1.x printed it: archive both tables, re-run the 0.1.x step. */
  private static void archiveRemedyState(String db) throws SQLException {
    applyReleased011(db);
    exec(
        db,
        "CREATE SCHEMA archive",
        "ALTER TABLE agentguard_audit SET SCHEMA archive",
        "ALTER TABLE agentguard_audit_anchor SET SCHEMA archive");
    applyReleased011(db);
  }

  private static ApplicationContextRunner runner(DataSource ds, String... properties) {
    return new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withBean(DataSource.class, () -> ds)
        .withPropertyValues("agentguard.enabled=true", "agentguard.audit.unkeyed=true")
        .withPropertyValues(properties);
  }

  private static AgentGuardException rootRefusal(AssertableApplicationContext ctx) {
    assertThat(ctx).hasFailed();
    Throwable t = ctx.getStartupFailure();
    while (t != null && !(t instanceof AgentGuardException)) {
      t = t.getCause();
    }
    assertThat(t).as("an AgentGuardException in the cause chain").isNotNull();
    return (AgentGuardException) t;
  }

  private static String guardsInPublic(String db) throws SQLException {
    return query(
        db,
        "SELECT pg_catalog.string_agg(t.tgenabled::text, '' ORDER BY t.tgname)"
            + " FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid"
            + " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
            + " WHERE NOT t.tgisinternal AND n.nspname = 'public'");
  }

  // ---- initialize-schema=true ----------------------------------------------------------------

  @Test
  void true_owner_empty_database_creates_arms_and_starts() throws Exception {
    String db = freshDatabase();
    runner(owner(db), "agentguard.jdbc.initialize-schema=true")
        .run(ctx -> assertThat(ctx).hasNotFailed().hasSingleBean(AgentGuardSchemaGate.class));
    assertThat(guardsInPublic(db)).isEqualTo("AAAAA");
  }

  @Test
  void true_owner_archived_state_is_repaired_by_the_corrected_script_and_starts() throws Exception {
    String db = freshDatabase();
    archiveRemedyState(db);
    runner(owner(db), "agentguard.jdbc.initialize-schema=true")
        .run(ctx -> assertThat(ctx).hasNotFailed());
    assertThat(guardsInPublic(db)).isEqualTo("AAAAA");
  }

  @Test
  void true_non_owner_on_a_guarded_schema_is_a_coded_refusal_naming_the_property()
      throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    runner(runtime(db), "agentguard.jdbc.initialize-schema=true")
        .run(
            ctx -> {
              var e = rootRefusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_CREATION_FAILED);
              assertThat(e.getMessage())
                  .contains("initialize-schema=false")
                  .doesNotContain("permission denied");
            });
  }

  @Test
  void true_non_owner_on_a_011_schema_is_refused_unguarded_naming_the_owner_step()
      throws Exception {
    String db = freshDatabase();
    applyReleased011(db);
    runner(runtime(db), "agentguard.jdbc.initialize-schema=true")
        .run(
            ctx -> {
              var e = rootRefusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
              assertThat(e.getMessage())
                  .contains("tgenabled=O", "as the role that owns")
                  .doesNotContain("permission denied");
            });
  }

  // ---- initialize-schema=false ---------------------------------------------------------------

  @Test
  void false_non_owner_on_a_guarded_schema_starts_and_writes() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    runner(runtime(db), "agentguard.jdbc.initialize-schema=false")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(
                      ctx.getBean(BudgetStore.class)
                          .incrementAndGet("k", 1, java.time.Duration.ofMinutes(1)))
                  .isEqualTo(1);
            });
  }

  @Test
  void false_on_the_archived_state_is_refused_and_nothing_is_created() throws Exception {
    String db = freshDatabase();
    archiveRemedyState(db);
    runner(runtime(db), "agentguard.jdbc.initialize-schema=false")
        .run(
            ctx -> {
              var e = rootRefusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
              assertThat(e.getMessage()).contains("agentguard_audit_append_only", "nspname");
            });
    assertThat(guardsInPublic(db)).isNull();
  }

  @Test
  void false_on_a_011_fresh_schema_is_refused_with_the_enable_always_remedy() throws Exception {
    String db = freshDatabase();
    applyReleased011(db);
    runner(runtime(db), "agentguard.jdbc.initialize-schema=false")
        .run(
            ctx -> {
              var e = rootRefusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
              assertThat(e.getMessage()).contains("tgenabled=O", "ENABLE ALWAYS");
            });
  }

  // ---- the paths that do not go through the default eager singletons -------------------------

  @Test
  void lazy_initialization_still_refuses_at_startup() throws Exception {
    String db = freshDatabase();
    archiveRemedyState(db);
    runner(
            runtime(db),
            "agentguard.jdbc.initialize-schema=false",
            "spring.main.lazy-initialization=true")
        .withInitializer(
            c ->
                c.addBeanFactoryPostProcessor(
                    new org.springframework.boot.LazyInitializationBeanFactoryPostProcessor()))
        .run(ctx -> assertThat(rootRefusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  /** CP34-1: the application's own JDBC stores remove no edge to the check, lazy or not. */
  @Test
  void user_supplied_stores_under_lazy_initialization_are_still_checked() throws Exception {
    String db = freshDatabase();
    archiveRemedyState(db);
    DataSource ds = runtime(db);
    runner(
            ds,
            "agentguard.store=JDBC",
            "agentguard.budgets.store=MEMORY",
            "agentguard.jdbc.initialize-schema=false",
            "spring.main.lazy-initialization=true")
        .withBean(DecisionStore.class, () -> new JdbcDecisionStore(ds))
        .withBean(AuditSink.class, () -> new JdbcAuditSink(ds))
        .withInitializer(
            c ->
                c.addBeanFactoryPostProcessor(
                    new org.springframework.boot.LazyInitializationBeanFactoryPostProcessor()))
        .run(ctx -> assertThat(rootRefusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  @Test
  void budget_only_jdbc_configuration_is_checked_too() throws Exception {
    String db = freshDatabase();
    archiveRemedyState(db);
    runner(
            runtime(db),
            "agentguard.store=MEMORY",
            "agentguard.budgets.store=JDBC",
            "agentguard.jdbc.initialize-schema=false")
        .run(ctx -> assertThat(rootRefusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  @Test
  void memory_only_context_never_builds_the_check_and_needs_no_data_source() {
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withPropertyValues(
            "agentguard.enabled=true", "agentguard.audit.unkeyed=true", "agentguard.store=MEMORY")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(DecisionStore.class)).isNotNull();
              assertThat(ctx.getBean(AuditSink.class)).isNotNull();
              assertThat(ctx.getBean(AgentGuardSchemaGate.class).verifiedDataSource()).isEmpty();
              assertThatThrownBy(() -> ctx.getBean(AgentGuardSchemaGate.class).dataSource())
                  .isInstanceOf(AgentGuardConfigurationException.class);
            });
  }

  /**
   * An owner-run migration in the same boot (the shape Flyway, Liquibase and {@code
   * spring.sql.init} share: a {@code DataSourceScriptDatabaseInitializer}-type bean), registered
   * after the starter so only the dependency declared on the gate puts it first.
   */
  @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
  @org.springframework.context.annotation.Import(
      org.springframework.boot.sql.init.dependency.DatabaseInitializationDependencyConfigurer.class)
  static class ZzOwnerMigrationConfiguration {
    @org.springframework.context.annotation.Bean
    org.springframework.boot.jdbc.init.DataSourceScriptDatabaseInitializer ownerMigration(
        DataSource ds) {
      return new org.springframework.boot.jdbc.init.DataSourceScriptDatabaseInitializer(
          ds, new org.springframework.boot.sql.init.DatabaseInitializationSettings()) {
        @Override
        public boolean initializeDatabase() {
          JdbcSupport.initializeSchema(ds);
          return true;
        }
      };
    }
  }

  @Test
  void schema_created_by_a_migration_in_the_same_boot_is_checked_after_it() throws Exception {
    String db = freshDatabase();
    new ApplicationContextRunner()
        .withConfiguration(
            AutoConfigurations.of(
                AgentGuardAutoConfiguration.class, ZzOwnerMigrationConfiguration.class))
        .withBean(DataSource.class, () -> owner(db))
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.jdbc.initialize-schema=false")
        .run(ctx -> assertThat(ctx).hasNotFailed());
    assertThat(guardsInPublic(db)).isEqualTo("AAAAA");
  }
}
