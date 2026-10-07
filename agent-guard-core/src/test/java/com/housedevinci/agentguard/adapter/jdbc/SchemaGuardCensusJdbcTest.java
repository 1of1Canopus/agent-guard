package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * The audit-trail guard census (advisory "schema trigger guards", 0.1.x): the bundled script scopes
 * its five trigger predicates to the relation and arms them {@code ENABLE ALWAYS}, and {@link
 * JdbcSupport#verifyGuards} refuses every state in which the append-only trail, the anchor or
 * keyed-from-birth does not hold. Each test runs in a database of its own.
 */
@Testcontainers
class SchemaGuardCensusJdbcTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  private static final AtomicInteger SEQ = new AtomicInteger();
  private static final String RUNTIME_PASSWORD = "census-runtime";

  private static final String[] FIVE = {
    "agentguard_audit_append_only",
    "agentguard_audit_no_truncate",
    "agentguard_audit_anchor_monotonic",
    "agentguard_audit_anchor_no_delete",
    "agentguard_audit_anchor_no_truncate"
  };

  // ---- fixtures -------------------------------------------------------------------------------

  private static String freshDatabase() throws SQLException {
    String db = "census_" + SEQ.incrementAndGet();
    try (Connection c = connect("test", POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement()) {
      st.execute("CREATE DATABASE " + db);
    }
    try (Connection c = connect(db, POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement()) {
      st.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC");
    }
    return db;
  }

  private static Connection connect(String db, String user, String password) throws SQLException {
    return DriverManager.getConnection(jdbcUrl(db), user, password);
  }

  private static String jdbcUrl(String db) {
    return "jdbc:postgresql://"
        + POSTGRES.getHost()
        + ":"
        + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
        + "/"
        + db;
  }

  private static DataSource owner(String db) {
    return dataSource(db, POSTGRES.getUsername(), POSTGRES.getPassword());
  }

  private static DataSource dataSource(String db, String user, String password) {
    var ds = new PGSimpleDataSource();
    ds.setUrl(jdbcUrl(db));
    ds.setUser(user);
    ds.setPassword(password);
    return ds;
  }

  private static void owner(String db, String... statements) throws SQLException {
    as(db, POSTGRES.getUsername(), POSTGRES.getPassword(), statements);
  }

  private static void as(String db, String user, String password, String... statements)
      throws SQLException {
    try (Connection c = connect(db, user, password);
        Statement st = c.createStatement()) {
      for (String s : statements) {
        st.execute(s);
      }
    }
  }

  private static String query(String db, String sql) throws SQLException {
    try (Connection c = connect(db, POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      List<String> rows = new ArrayList<>();
      while (rs.next()) {
        List<String> cols = new ArrayList<>();
        for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
          cols.add(rs.getString(i));
        }
        rows.add(String.join("|", cols));
      }
      return String.join(";", rows);
    }
  }

  /** The script exactly as 0.1.0 and 0.1.1 shipped it (test resource, byte copy of the tag). */
  private static void applyReleased011(String db) throws SQLException {
    owner(
        db,
        "BEGIN",
        resource("/com/housedevinci/agentguard/schema-postgresql-0.1.1.sql"),
        "COMMIT");
  }

  private static String resource(String path) {
    try (InputStream in = SchemaGuardCensusJdbcTest.class.getResourceAsStream(path)) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String runtimeRole(String db) throws SQLException {
    String role = "rt_" + db;
    owner(
        db,
        "CREATE ROLE " + role + " LOGIN PASSWORD '" + RUNTIME_PASSWORD + "'",
        "GRANT SELECT, INSERT ON agentguard_audit TO " + role,
        "GRANT USAGE ON SEQUENCE agentguard_audit_seq_seq TO " + role,
        "GRANT SELECT, INSERT, UPDATE ON agentguard_decision, agentguard_audit_anchor TO " + role,
        "GRANT SELECT, INSERT, UPDATE, DELETE ON agentguard_budget TO " + role);
    return role;
  }

  private static String triggers(String db, String schema) throws SQLException {
    return query(
        db,
        "SELECT t.tgname || ':' || t.tgenabled::text FROM pg_catalog.pg_trigger t"
            + " JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid"
            + " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
            + " WHERE NOT t.tgisinternal AND n.nspname = '"
            + schema
            + "' ORDER BY 1");
  }

  private static AgentGuardException refusal(DataSource ds) {
    var thrown = org.assertj.core.api.Assertions.catchThrowable(() -> JdbcSupport.verifyGuards(ds));
    assertThat(thrown).isInstanceOf(AgentGuardException.class);
    return (AgentGuardException) thrown;
  }

  private static void assertUnguarded(DataSource ds, String... fragments) {
    var e = refusal(ds);
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(e.getMessage()).contains(fragments);
  }

  // ---- the healthy paths ----------------------------------------------------------------------

  @Test
  void fresh_install_creates_all_five_guards_enable_always_and_verifies_clean() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchemaAndVerifyGuards(owner(db));

    assertThat(triggers(db, "public"))
        .isEqualTo(
            "agentguard_audit_anchor_monotonic:A;agentguard_audit_anchor_no_delete:A;"
                + "agentguard_audit_anchor_no_truncate:A;agentguard_audit_append_only:A;"
                + "agentguard_audit_no_truncate:A");
    assertThatCode(() -> JdbcSupport.verifyGuards(owner(db))).doesNotThrowAnyException();
    // idempotent: a second run changes nothing and still verifies
    JdbcSupport.initializeSchemaAndVerifyGuards(owner(db));
    assertThat(query(db, "SELECT count(*) FROM pg_catalog.pg_trigger WHERE NOT tgisinternal"))
        .isEqualTo("5");
  }

  @Test
  void runtime_role_with_only_the_documented_grants_verifies_a_guarded_schema() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    String role = runtimeRole(db);

    assertThatCode(() -> JdbcSupport.verifyGuards(dataSource(db, role, RUNTIME_PASSWORD)))
        .doesNotThrowAnyException();
  }

  @Test
  void enable_always_makes_the_guard_fire_in_replica_mode() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(
        db,
        "INSERT INTO agentguard_audit (ts, principal_id, tool, args_hash, decision, key_id,"
            + " prev_hash, hash) VALUES (now(), 'p', 't', 'h', 'ALLOW', 'none', repeat('0', 64),"
            + " repeat('1', 64))");

    assertThatThrownBy(
            () ->
                owner(db, "SET session_replication_role = replica", "DELETE FROM agentguard_audit"))
        .hasMessageContaining("agentguard_audit is append-only");
    assertThat(query(db, "SELECT count(*) FROM agentguard_audit")).isEqualTo("1");
  }

  // ---- the advisory's two reachability paths --------------------------------------------------

  @Test
  void archive_remedy_state_is_refused_and_the_corrected_script_repairs_it() throws Exception {
    String db = freshDatabase();
    applyReleased011(db);
    owner(
        db,
        "CREATE SCHEMA archive",
        "ALTER TABLE agentguard_audit SET SCHEMA archive",
        "ALTER TABLE agentguard_audit_anchor SET SCHEMA archive");
    applyReleased011(db); // the AG-AUDIT-002 remedy as 0.1.x printed it
    assertThat(triggers(db, "public")).isEmpty();

    assertUnguarded(
        owner(db),
        "agentguard_audit_append_only",
        "agentguard_audit_anchor_no_truncate",
        "missing",
        "nspname");

    JdbcSupport.initializeSchemaAndVerifyGuards(owner(db));
    assertThat(triggers(db, "public"))
        .doesNotContain(":O")
        .contains("agentguard_audit_append_only:A");
    assertThat(triggers(db, "public").split(";")).hasSize(5);
    // the archived copies are untouched and collide with nothing
    assertThat(triggers(db, "archive").split(";")).hasSize(5).allMatch(t -> t.endsWith(":O"));
  }

  @Test
  void archive_remedy_with_only_the_audit_table_archived_is_repaired() throws Exception {
    String db = freshDatabase();
    applyReleased011(db);
    owner(db, "CREATE SCHEMA archive", "ALTER TABLE agentguard_audit SET SCHEMA archive");
    applyReleased011(db);

    assertUnguarded(owner(db), "agentguard_audit_append_only", "agentguard_audit_no_truncate");
    JdbcSupport.initializeSchemaAndVerifyGuards(owner(db));
    assertThat(triggers(db, "public").split(";")).hasSize(5).allMatch(t -> t.endsWith(":A"));
  }

  @Test
  void same_named_trigger_on_an_unrelated_relation_no_longer_suppresses_the_guard()
      throws Exception {
    String db = freshDatabase();
    List<String> decoys = new ArrayList<>();
    decoys.add("CREATE TABLE unrelated (id int)");
    decoys.add(
        "CREATE FUNCTION unrelated_noop() RETURNS trigger AS $$ BEGIN RETURN NEW; END; $$"
            + " LANGUAGE plpgsql");
    for (String name : FIVE) {
      decoys.add(
          "CREATE TRIGGER "
              + name
              + " BEFORE INSERT ON unrelated FOR EACH ROW EXECUTE FUNCTION"
              + " unrelated_noop()");
    }
    owner(db, decoys.toArray(String[]::new));

    JdbcSupport.initializeSchemaAndVerifyGuards(owner(db));
    assertThat(
            query(
                db,
                "SELECT count(*) FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON"
                    + " c.oid = t.tgrelid WHERE c.relname LIKE 'agentguard%' AND t.tgenabled ="
                    + " 'A'"))
        .isEqualTo("5");
  }

  @Test
  void released_011_script_alone_leaves_triggers_at_origin_and_is_refused() throws Exception {
    String db = freshDatabase();
    applyReleased011(db);

    assertUnguarded(owner(db), "tgenabled=O", "ENABLE ALWAYS", "schema-postgresql.sql");
    JdbcSupport.initializeSchema(owner(db));
    assertThatCode(() -> JdbcSupport.verifyGuards(owner(db))).doesNotThrowAnyException();
  }

  // ---- §4.4: the exact trigger set and its per-trigger columns --------------------------------

  @Test
  void disabled_and_replica_triggers_are_refused() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(db, "ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only");
    assertUnguarded(owner(db), "agentguard_audit_append_only", "tgenabled=D");
    owner(db, "ALTER TABLE agentguard_audit ENABLE REPLICA TRIGGER agentguard_audit_append_only");
    assertUnguarded(owner(db), "agentguard_audit_append_only", "tgenabled=R");
  }

  @Test
  void trigger_pointed_at_a_same_shaped_noop_function_is_refused() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(
        db,
        "CREATE FUNCTION zz_noop() RETURNS trigger AS $$ BEGIN RETURN OLD; END; $$ LANGUAGE"
            + " plpgsql",
        "DROP TRIGGER agentguard_audit_append_only ON agentguard_audit",
        "CREATE TRIGGER agentguard_audit_append_only BEFORE UPDATE OR DELETE ON agentguard_audit"
            + " FOR EACH ROW EXECUTE FUNCTION zz_noop()",
        "ALTER TABLE agentguard_audit ENABLE ALWAYS TRIGGER agentguard_audit_append_only");
    assertUnguarded(owner(db), "agentguard_audit_append_only", "zz_noop");
  }

  @Test
  void guard_body_swapped_in_place_is_refused_without_printing_the_body() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(
        db,
        "CREATE OR REPLACE FUNCTION agentguard_audit_append_only() RETURNS trigger AS $$"
            + " BEGIN RETURN OLD; END; $$ LANGUAGE plpgsql");
    var e = refusal(owner(db));
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(e.getMessage())
        .contains("agentguard_audit_append_only", "length", "md5")
        .doesNotContain("RETURN OLD")
        .doesNotContain("append-only (attempted");
  }

  @Test
  void a_lone_carriage_return_in_a_guard_body_is_refused_and_crlf_is_not() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    String crlf =
        "CREATE OR REPLACE FUNCTION agentguard_audit_append_only() RETURNS trigger AS $$\r\n"
            + "BEGIN\r\n"
            + "  RAISE EXCEPTION 'agentguard_audit is append-only (attempted %)', TG_OP;\r\n"
            + "END;\r\n"
            + "$$ LANGUAGE plpgsql";
    owner(db, crlf);
    assertThatCode(() -> JdbcSupport.verifyGuards(owner(db))).doesNotThrowAnyException();

    owner(
        db,
        "SET check_function_bodies = off",
        "CREATE OR REPLACE FUNCTION agentguard_audit_append_only() RETURNS trigger AS $$\n"
            + "BEGIN\n"
            + "  -- nothing to see here\rRETURN OLD;\n"
            + "  RAISE EXCEPTION 'agentguard_audit is append-only (attempted %)', TG_OP;\n"
            + "END;\n"
            + "$$ LANGUAGE plpgsql");
    assertUnguarded(owner(db), "agentguard_audit_append_only", "carriage return");
  }

  @Test
  void when_clause_and_column_list_are_refused() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(
        db,
        "DROP TRIGGER agentguard_audit_append_only ON agentguard_audit",
        "CREATE TRIGGER agentguard_audit_append_only BEFORE UPDATE OR DELETE ON agentguard_audit"
            + " FOR EACH ROW WHEN (false) EXECUTE FUNCTION agentguard_audit_append_only()",
        "ALTER TABLE agentguard_audit ENABLE ALWAYS TRIGGER agentguard_audit_append_only",
        "DROP TRIGGER agentguard_audit_anchor_monotonic ON agentguard_audit_anchor",
        "CREATE TRIGGER agentguard_audit_anchor_monotonic BEFORE UPDATE OF updated_at ON"
            + " agentguard_audit_anchor FOR EACH ROW EXECUTE FUNCTION"
            + " agentguard_audit_anchor_monotonic()",
        "ALTER TABLE agentguard_audit_anchor ENABLE ALWAYS TRIGGER"
            + " agentguard_audit_anchor_monotonic");
    assertUnguarded(
        owner(db),
        "agentguard_audit_append_only",
        "WHEN clause",
        "agentguard_audit_anchor_monotonic",
        "column list");
  }

  @Test
  void a_sixth_trigger_on_any_of_the_four_tables_is_refused() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(
        db,
        "CREATE FUNCTION zz_quiet() RETURNS trigger AS $$ BEGIN RETURN NULL; END; $$ LANGUAGE"
            + " plpgsql",
        "CREATE TRIGGER zz_quiet BEFORE INSERT ON agentguard_audit FOR EACH ROW EXECUTE FUNCTION"
            + " zz_quiet()");
    // shown first: the sixth trigger empties the trail with no error
    owner(
        db,
        "INSERT INTO agentguard_audit (ts, principal_id, tool, args_hash, decision, key_id,"
            + " prev_hash, hash) VALUES (now(), 'p', 't', 'h', 'ALLOW', 'none', repeat('0', 64),"
            + " repeat('1', 64))");
    assertThat(query(db, "SELECT count(*) FROM agentguard_audit")).isEqualTo("0");
    assertUnguarded(owner(db), "zz_quiet", "agentguard_audit", "not one of the bundled guards");

    owner(
        db,
        "DROP TRIGGER zz_quiet ON agentguard_audit",
        "CREATE CONSTRAINT TRIGGER zz_constraint AFTER INSERT ON agentguard_audit FOR EACH ROW"
            + " EXECUTE FUNCTION zz_quiet()");
    assertUnguarded(owner(db), "zz_constraint");

    owner(
        db,
        "DROP TRIGGER zz_constraint ON agentguard_audit",
        "CREATE TRIGGER zz_decision BEFORE UPDATE ON agentguard_decision FOR EACH ROW EXECUTE"
            + " FUNCTION zz_quiet()",
        "CREATE TRIGGER zz_budget BEFORE DELETE ON agentguard_budget FOR EACH ROW EXECUTE"
            + " FUNCTION zz_quiet()");
    assertUnguarded(owner(db), "zz_decision", "agentguard_decision", "zz_budget");
  }

  @Test
  void a_sixth_trigger_owned_by_another_role_is_refused_the_same_way() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    String other = "other_" + db;
    owner(
        db,
        "CREATE ROLE " + other,
        "CREATE SCHEMA other_fn AUTHORIZATION " + other,
        "SET ROLE " + other,
        "CREATE FUNCTION other_fn.rewrite() RETURNS trigger AS $$ BEGIN NEW.decision := 'ALLOW';"
            + " RETURN NEW; END; $$ LANGUAGE plpgsql",
        "RESET ROLE",
        "CREATE TRIGGER zz_rewrite BEFORE INSERT ON agentguard_audit FOR EACH ROW EXECUTE"
            + " FUNCTION other_fn.rewrite()");
    assertUnguarded(owner(db), "zz_rewrite");
  }

  @Test
  void a_dropped_guard_is_refused_and_the_script_recreates_it() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(db, "DROP TRIGGER agentguard_audit_anchor_no_delete ON agentguard_audit_anchor");
    assertUnguarded(owner(db), "agentguard_audit_anchor_no_delete", "missing");
    JdbcSupport.initializeSchemaAndVerifyGuards(owner(db));
  }

  // ---- §4.5: rules, RLS, policies, inheritance ------------------------------------------------

  @Test
  void a_do_instead_rule_is_refused_on_the_trail_and_on_the_budget_table() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(db, "CREATE RULE zz_swallow AS ON INSERT TO agentguard_audit DO INSTEAD NOTHING");
    assertUnguarded(owner(db), "zz_swallow", "rule");
    owner(
        db,
        "DROP RULE zz_swallow ON agentguard_audit",
        "CREATE RULE zz_stuck AS ON DELETE TO agentguard_budget DO INSTEAD NOTHING");
    assertUnguarded(owner(db), "zz_stuck", "agentguard_budget");
  }

  @Test
  void row_level_security_and_a_dormant_policy_are_refused() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(db, "CREATE POLICY zz_pol ON agentguard_audit USING (true)");
    assertUnguarded(owner(db), "zz_pol", "policy");
    owner(
        db,
        "DROP POLICY zz_pol ON agentguard_audit",
        "ALTER TABLE agentguard_decision ENABLE ROW LEVEL SECURITY");
    assertUnguarded(owner(db), "agentguard_decision", "row level security");
    owner(
        db,
        "ALTER TABLE agentguard_decision DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE agentguard_audit_anchor FORCE ROW LEVEL SECURITY");
    assertUnguarded(owner(db), "agentguard_audit_anchor", "row level security");
  }

  @Test
  void an_inheritance_child_of_the_trail_is_refused() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    owner(db, "CREATE TABLE zz_child () INHERITS (agentguard_audit)");
    assertUnguarded(owner(db), "zz_child", "inherit");
  }

  // ---- §4.9: verification's own names and the pin ---------------------------------------------

  /**
   * B-38-10 shape: the runtime role owns a schema of its own, first on its search_path ahead of
   * pg_catalog, and plants a {@code current_schema()} that answers with a schema whose guards are
   * intact. Unqualified, the census would read the guarded decoy and pass an unguarded trail.
   */
  @Test
  void shadowed_catalogue_functions_do_not_change_the_answer() throws Exception {
    String db = freshDatabase();
    applyReleased011(db);
    // a fully guarded copy in "decoy", the live trail in public left at 0.1.1 (O) and then
    // stripped of its guards
    owner(
        db,
        "CREATE SCHEMA decoy",
        "SET search_path = decoy",
        resource("/com/housedevinci/agentguard/schema-postgresql.sql"),
        "RESET search_path",
        "DROP TRIGGER agentguard_audit_append_only ON public.agentguard_audit");
    String role = runtimeRole(db);
    owner(
        db,
        "GRANT USAGE ON SCHEMA decoy TO " + role,
        "CREATE SCHEMA app AUTHORIZATION " + role,
        "ALTER ROLE " + role + " IN DATABASE " + db + " SET search_path = public, app, pg_catalog");
    as(
        db,
        role,
        RUNTIME_PASSWORD,
        "CREATE FUNCTION app.current_schema() RETURNS name AS $$ SELECT 'decoy'::name $$ LANGUAGE"
            + " sql",
        "CREATE FUNCTION app.set_config(text, text, boolean) RETURNS text AS $$ SELECT $2 $$"
            + " LANGUAGE sql",
        "CREATE FUNCTION app.current_setting(text) RETURNS text AS $$ SELECT 'pg_catalog'::text"
            + " $$ LANGUAGE sql");
    // the fixture is real: unqualified, the role's session answers about the decoy
    try (Connection c = connect(db, role, RUNTIME_PASSWORD);
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery("SELECT current_schema()")) {
      rs.next();
      assertThat(rs.getString(1)).isEqualTo("decoy");
    }

    var e = refusal(dataSource(db, role, RUNTIME_PASSWORD));
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(e.getMessage()).contains("schema public").contains("agentguard_audit_append_only");
  }

  @Test
  void the_search_path_pin_is_read_back_and_holds_on_the_happy_path() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    String role = runtimeRole(db);
    owner(
        db,
        "CREATE SCHEMA app AUTHORIZATION " + role,
        "ALTER ROLE " + role + " IN DATABASE " + db + " SET search_path = public, app, pg_catalog");
    as(
        db,
        role,
        RUNTIME_PASSWORD,
        "CREATE FUNCTION app.md5(text) RETURNS text AS $$ SELECT 'SHADOWED'::text $$ LANGUAGE"
            + " sql");
    assertThatCode(() -> JdbcSupport.verifyGuards(dataSource(db, role, RUNTIME_PASSWORD)))
        .doesNotThrowAnyException();
  }

  // ---- unverifiable is not clean --------------------------------------------------------------

  @Test
  void a_catalogue_the_role_cannot_read_is_unverifiable_not_clean() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    String role = runtimeRole(db);
    owner(db, "REVOKE SELECT ON pg_catalog.pg_trigger FROM PUBLIC");
    try {
      var e = refusal(dataSource(db, role, RUNTIME_PASSWORD));
      assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
      assertThat(e.getMessage()).contains("pg_trigger").contains("SQLState");
    } finally {
      owner(db, "GRANT SELECT ON pg_catalog.pg_trigger TO PUBLIC");
    }
    owner(db, "REVOKE SELECT ON pg_catalog.pg_proc FROM PUBLIC");
    try {
      assertThat(refusal(dataSource(db, role, RUNTIME_PASSWORD)).code())
          .isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    } finally {
      owner(db, "GRANT SELECT ON pg_catalog.pg_proc TO PUBLIC");
    }
  }

  @Test
  void no_current_schema_is_unverifiable_not_clean() throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    String role = runtimeRole(db);
    owner(db, "ALTER ROLE " + role + " IN DATABASE " + db + " SET search_path = nowhere");
    var e = refusal(dataSource(db, role, RUNTIME_PASSWORD));
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    assertThat(e.getMessage()).contains("currentSchema");
  }

  @Test
  void an_empty_database_is_refused_as_unguarded() throws Exception {
    String db = freshDatabase();
    assertUnguarded(owner(db), "agentguard_audit", "not found");
  }

  // ---- the creation path run by a role that does not own the schema ---------------------------

  @Test
  void non_owner_creation_on_a_guarded_schema_is_a_coded_refusal_not_a_raw_sql_error()
      throws Exception {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    String role = runtimeRole(db);

    var thrown =
        org.assertj.core.api.Assertions.catchThrowable(
            () ->
                JdbcSupport.initializeSchemaAndVerifyGuards(
                    dataSource(db, role, RUNTIME_PASSWORD)));
    assertThat(thrown).isInstanceOf(AgentGuardException.class);
    var e = (AgentGuardException) thrown;
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_CREATION_FAILED);
    assertThat(e.getMessage())
        .contains("initialize-schema=false", "42501", "guards are in place")
        .doesNotContain("permission denied");
  }

  @Test
  void non_owner_creation_on_an_unguarded_schema_names_the_owner_step() throws Exception {
    String db = freshDatabase();
    applyReleased011(db);
    String role = runtimeRole(db);

    var thrown =
        org.assertj.core.api.Assertions.catchThrowable(
            () ->
                JdbcSupport.initializeSchemaAndVerifyGuards(
                    dataSource(db, role, RUNTIME_PASSWORD)));
    assertThat(thrown).isInstanceOf(AgentGuardException.class);
    var e = (AgentGuardException) thrown;
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(e.getMessage())
        .contains("tgenabled=O", "as the role that owns")
        .doesNotContain("permission denied");
  }

  @Test
  void creation_that_ends_unguarded_is_refused_and_rolled_back() throws Exception {
    String db = freshDatabase();
    owner(db, "CREATE SCHEMA keep");
    // a pre-existing extra trigger survives the script: the census refuses inside the same
    // transaction, so nothing the script did is committed
    JdbcSupport.initializeSchema(owner(db));
    owner(
        db,
        "CREATE FUNCTION zz_quiet() RETURNS trigger AS $$ BEGIN RETURN NULL; END; $$ LANGUAGE"
            + " plpgsql",
        "CREATE TRIGGER zz_quiet BEFORE INSERT ON agentguard_audit FOR EACH ROW EXECUTE FUNCTION"
            + " zz_quiet()",
        "ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_no_truncate");
    var thrown =
        org.assertj.core.api.Assertions.catchThrowable(
            () -> JdbcSupport.initializeSchemaAndVerifyGuards(owner(db)));
    assertThat(thrown).isInstanceOf(AgentGuardException.class);
    assertThat(((AgentGuardException) thrown).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    // rolled back: the script's ENABLE ALWAYS on the disabled trigger did not commit
    assertThat(triggers(db, "public")).contains("agentguard_audit_no_truncate:D");
  }
}
