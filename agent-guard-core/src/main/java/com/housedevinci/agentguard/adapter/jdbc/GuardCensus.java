package com.housedevinci.agentguard.adapter.jdbc;

import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Startup check that the audit trail's guards hold in the schema the application uses.
 *
 * <p>Reads the catalogue only, on the caller's connection and inside the caller's transaction:
 *
 * <ol>
 *   <li>captures {@code pg_catalog.current_schema()} first, then pins {@code search_path} to {@code
 *       pg_catalog} for the transaction and reads the pin back, so no function name the check
 *       issues can resolve to a same-named function a role planted earlier on its path;
 *   <li>the non-internal triggers on the four tables are exactly the five bundled guards, each on
 *       its relation, {@code ENABLE ALWAYS}, with no {@code WHEN} clause and no column list, firing
 *       on the bundled events and pointing at the bundled function in the same schema;
 *   <li>each guard function's body equals the body in the bundled script (compared in Java, after
 *       folding CRLF to LF and trimming; any other carriage return is a refusal);
 *   <li>each of the four tables present is an ordinary ({@code relkind = 'r'}), logged ({@code
 *       relpersistence = 'p'}) table: an {@code UNLOGGED} table is emptied by crash recovery with
 *       no trigger firing, and is not replicated;
 *   <li>no rule, row level security flag, policy or inheritance edge on any of the four tables.
 * </ol>
 *
 * <p>Every name read from the catalogue or the session enters a finding through {@link
 * #display(String)}, so a name carrying a line break cannot forge a line in the startup log.
 *
 * <p>Every relation is named by the captured schema or by {@code pg_catalog}; every function is
 * {@code pg_catalog}-qualified as well as pinned. A finding is {@link ErrorCodes#SCHEMA_UNGUARDED};
 * a check that cannot complete is {@link ErrorCodes#SCHEMA_UNVERIFIABLE}, never a pass.
 */
final class GuardCensus {

  static final String SCRIPT = "/com/housedevinci/agentguard/schema-postgresql.sql";

  private static final List<String> TABLES =
      List.of(
          "agentguard_decision",
          "agentguard_audit",
          "agentguard_audit_anchor",
          "agentguard_budget");

  private static final String AUDIT = "agentguard_audit";
  private static final String ANCHOR = "agentguard_audit_anchor";

  /** One bundled guard: name, relation, function, and {@code pg_trigger.tgtype}. */
  private record Guard(String name, String table, String function, int tgtype) {}

  // tgtype: 27 = ROW|BEFORE|DELETE|UPDATE, 34 = BEFORE|TRUNCATE (statement), 19 =
  // ROW|BEFORE|UPDATE,
  // 11 = ROW|BEFORE|DELETE
  private static final List<Guard> GUARDS =
      List.of(
          new Guard("agentguard_audit_append_only", AUDIT, "agentguard_audit_append_only", 27),
          new Guard("agentguard_audit_no_truncate", AUDIT, "agentguard_audit_append_only", 34),
          new Guard(
              "agentguard_audit_anchor_monotonic", ANCHOR, "agentguard_audit_anchor_monotonic", 19),
          new Guard(
              "agentguard_audit_anchor_no_delete",
              ANCHOR,
              "agentguard_audit_anchor_append_only",
              11),
          new Guard(
              "agentguard_audit_anchor_no_truncate",
              ANCHOR,
              "agentguard_audit_anchor_append_only",
              34));

  private static final Set<String> FUNCTIONS =
      Set.of(
          "agentguard_audit_append_only",
          "agentguard_audit_anchor_monotonic",
          "agentguard_audit_anchor_append_only");

  private static final Pattern FUNCTION_BODY =
      Pattern.compile(
          "CREATE OR REPLACE FUNCTION (\\w+)\\(\\) RETURNS trigger AS \\$\\$(.*?)\\$\\$ LANGUAGE"
              + " plpgsql;",
          Pattern.DOTALL);

  private static final String IN_FOUR = "(?, ?, ?, ?)";

  private static final String CATALOGUES =
      "pg_catalog.pg_namespace, pg_class, pg_trigger, pg_proc, pg_language, pg_rewrite, pg_policy"
          + " and pg_inherits";

  private static final String REMEDY =
      " Remedy: apply the bundled schema-postgresql.sql once as the role that owns the tables (it"
          + " creates a missing guard and sets all five to ENABLE ALWAYS; it changes no row of the"
          + " trail or the anchor), drop any extra trigger, rule, policy or child table named"
          + " above, run ALTER TABLE ... SET LOGGED on any table named UNLOGGED, then restart. Run the application as a role that does not own the tables."
          + " See docs/upgrading-0.1.2.md. No property downgrades this refusal.";

  private static final String ARCHIVE_SENTENCE =
      " Every guard of a table is missing, which is the state 0.1.0 and 0.1.1 left behind when a"
          + " trail was archived (ALTER TABLE ... SET SCHEMA) and the schema step re-run, or when a"
          + " trigger of the same name existed on another relation (security advisory, audit"
          + " trail guards on 0.1.0 and 0.1.1). Check with: SELECT n.nspname, t.tgname, t.tgenabled FROM"
          + " pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid JOIN"
          + " pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE NOT t.tgisinternal AND"
          + " t.tgname LIKE 'agentguard%' ORDER BY 1, 2; and read nspname, never the bare"
          + " relation name. Before repairing, record the chain verifier's output and the trail's"
          + " row count against the anchor's row_count, and keep any disagreement: it is evidence.";

  private final Map<String, String> expectedBodies;

  private GuardCensus(Map<String, String> expectedBodies) {
    this.expectedBodies = expectedBodies;
  }

  /** The census over the bodies the bundled script carries. */
  static GuardCensus fromBundledScript(String script) {
    Map<String, String> bodies = new LinkedHashMap<>();
    Matcher m = FUNCTION_BODY.matcher(script);
    while (m.find()) {
      bodies.put(m.group(1), m.group(2));
    }
    if (!bodies.keySet().equals(FUNCTIONS)) {
      throw new AgentGuardException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "agentguard: the bundled schema-postgresql.sql did not yield exactly the three guard"
              + " functions "
              + FUNCTIONS
              + " (found "
              + bodies.keySet()
              + "); the jar is damaged or modified, so the audit trail guards cannot be verified.");
    }
    return new GuardCensus(Map.copyOf(bodies));
  }

  /** Runs the census on {@code c}, inside the transaction the caller opened. */
  void verify(Connection c) {
    String schema = null;
    try {
      schema = captureAndPin(c);
      String where = where(c, schema);
      List<String> findings = new ArrayList<>();
      tables(c, schema, findings);
      triggers(c, schema, findings);
      rules(c, schema, findings);
      policies(c, schema, findings);
      inheritance(c, schema, findings);
      if (!findings.isEmpty()) {
        throw new AgentGuardException(
            ErrorCodes.SCHEMA_UNGUARDED,
            "agentguard: the audit trail guards do not hold in "
                + where
                + ": "
                + String.join("; ", findings)
                + "."
                + REMEDY);
      }
    } catch (SQLException e) {
      throw unverifiable(schema, e);
    }
  }

  static AgentGuardException unverifiable(String schema, SQLException e) {
    return new AgentGuardException(
        ErrorCodes.SCHEMA_UNVERIFIABLE,
        "agentguard: could not verify the audit trail guards"
            + (schema == null ? "" : " in schema " + display(schema))
            + ": a catalogue read failed (SQLState "
            + e.getSQLState()
            + "). The check reads "
            + CATALOGUES
            + "; the application's role needs SELECT on each, which PUBLIC holds by default. A"
            + " schema migration in flight is another explanation: restart once it has committed."
            + " Unverifiable is refused, never treated as clean.");
  }

  private static String captureAndPin(Connection c) throws SQLException {
    String schema = single(c, "SELECT pg_catalog.current_schema()");
    if (schema == null) {
      throw new AgentGuardException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "agentguard: no current schema: every schema on the role's search_path is missing or"
              + " not visible to it, so the audit trail guards cannot be verified. Set"
              + " currentSchema=<schema> in the JDBC URL, or grant USAGE on the schema that holds"
              + " the agentguard tables.");
    }
    single(c, "SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)");
    String pinned = single(c, "SELECT pg_catalog.current_setting('search_path')");
    if (!"pg_catalog".equals(pinned)) {
      throw new AgentGuardException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "agentguard: could not pin search_path to pg_catalog for the audit trail guard check in"
              + " schema "
              + display(schema)
              + " (the check must run inside a transaction); unverifiable is refused, never"
              + " treated as clean.");
    }
    return schema;
  }

  private static String where(Connection c, String schema) throws SQLException {
    try (Statement st = c.createStatement();
        ResultSet rs = st.executeQuery("SELECT current_user, pg_catalog.current_database()")) {
      rs.next();
      return "schema "
          + display(schema)
          + " of database "
          + display(rs.getString(2))
          + " (role "
          + display(rs.getString(1))
          + ")";
    }
  }

  private static String single(Connection c, String sql) throws SQLException {
    try (Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      rs.next();
      return rs.getString(1);
    }
  }

  private static PreparedStatement scoped(Connection c, String sql, String schema, int schemas)
      throws SQLException {
    PreparedStatement ps = c.prepareStatement(sql);
    int i = 1;
    for (int s = 0; s < schemas; s++) {
      ps.setString(i++, schema);
      for (String t : TABLES) {
        ps.setString(i++, t);
      }
    }
    return ps;
  }

  private static void tables(Connection c, String schema, List<String> findings)
      throws SQLException {
    Set<String> present = new LinkedHashSet<>();
    try (PreparedStatement ps =
            scoped(
                c,
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, c.relkind,"
                    + " c.relpersistence"
                    + " FROM pg_catalog.pg_class c"
                    + " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                    + " WHERE n.nspname = ? AND c.relname IN "
                    + IN_FOUR,
                schema,
                1);
        ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        String table = rs.getString(1);
        present.add(table);
        String shown = display(schema) + "." + display(table);
        if (rs.getBoolean(2) || rs.getBoolean(3)) {
          findings.add(shown + " has row level security enabled or forced");
        }
        String kind = rs.getString(4);
        if (!"r".equals(kind)) {
          findings.add(
              shown
                  + " is not an ordinary table (relkind="
                  + display(kind)
                  + ", expected r); the guards are only checked on an ordinary table");
        }
        String persistence = rs.getString(5);
        if (!"p".equals(persistence)) {
          findings.add(
              shown
                  + " is "
                  + ("u".equals(persistence) ? "UNLOGGED" : "not a permanent logged table")
                  + " (relpersistence="
                  + display(persistence)
                  + ", expected p); a crash empties an unlogged table with no trigger firing");
        }
      }
    }
    for (String table : List.of(AUDIT, ANCHOR)) {
      if (!present.contains(table)) {
        findings.add(
            "table " + display(schema) + "." + table + " not found, so none of its guards exist");
      }
    }
  }

  private void triggers(Connection c, String schema, List<String> findings) throws SQLException {
    Map<String, Guard> expected = new LinkedHashMap<>();
    for (Guard g : GUARDS) {
      expected.put(g.table() + "." + g.name(), g);
    }
    Set<String> seen = new LinkedHashSet<>();
    Set<String> bodiesChecked = new LinkedHashSet<>();
    try (PreparedStatement ps =
            scoped(
                c,
                "SELECT c.relname, t.tgname, t.tgtype, t.tgenabled, t.tgqual IS NULL,"
                    + " t.tgattr::pg_catalog.text, p.proname, pn.nspname, p.prokind, p.pronargs,"
                    + " l.lanname, p.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype,"
                    + " p.prosecdef, p.proconfig IS NULL, p.prosrc"
                    + " FROM pg_catalog.pg_trigger t"
                    + " JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid"
                    + " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                    + " JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid"
                    + " JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace"
                    + " JOIN pg_catalog.pg_language l ON l.oid = p.prolang"
                    + " WHERE NOT t.tgisinternal AND n.nspname = ? AND c.relname IN "
                    + IN_FOUR
                    + " ORDER BY c.relname, t.tgname",
                schema,
                1);
        ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        String table = rs.getString(1);
        String name = rs.getString(2);
        String label = "trigger " + display(name) + " on " + display(schema) + "." + display(table);
        Guard g = expected.get(table + "." + name);
        if (g == null) {
          findings.add(label + " is not one of the bundled guards");
          continue;
        }
        seen.add(table + "." + name);
        if (rs.getInt(3) != g.tgtype()) {
          findings.add(label + " fires on tgtype=" + rs.getInt(3) + ", expected " + g.tgtype());
        }
        String enabled = rs.getString(4);
        if (!"A".equals(enabled)) {
          findings.add(
              label + " is tgenabled=" + display(enabled) + ", expected ENABLE ALWAYS (A)");
        }
        if (!rs.getBoolean(5)) {
          findings.add(label + " carries a WHEN clause");
        }
        String attr = rs.getString(6);
        if (attr != null && !attr.isBlank()) {
          findings.add(label + " carries a column list (UPDATE OF ...)");
        }
        String fn = rs.getString(7);
        String fnSchema = rs.getString(8);
        boolean shape =
            "f".equals(rs.getString(9))
                && rs.getInt(10) == 0
                && "plpgsql".equals(rs.getString(11))
                && rs.getBoolean(12)
                && !rs.getBoolean(13)
                && rs.getBoolean(14);
        if (!g.function().equals(fn) || !schema.equals(fnSchema) || !shape) {
          findings.add(
              label
                  + " points at function "
                  + display(fnSchema)
                  + "."
                  + display(fn)
                  + ", expected the bundled "
                  + display(schema)
                  + "."
                  + g.function()
                  + "() (plpgsql, no arguments, not SECURITY DEFINER, no SET clause)");
        } else if (bodiesChecked.add(fn)) {
          body(fn, rs.getString(15), findings);
        }
      }
    }
    Map<String, Integer> missingPerTable = new LinkedHashMap<>();
    for (var e : expected.entrySet()) {
      if (!seen.contains(e.getKey())) {
        Guard g = e.getValue();
        findings.add(
            "trigger " + g.name() + " on " + display(schema) + "." + g.table() + " is missing");
        missingPerTable.merge(g.table(), 1, Integer::sum);
      }
    }
    boolean wholeTableMissing =
        missingPerTable.getOrDefault(AUDIT, 0) == 2 || missingPerTable.getOrDefault(ANCHOR, 0) == 3;
    if (wholeTableMissing) {
      findings.add(ARCHIVE_SENTENCE.strip());
    }
  }

  private void body(String function, String actual, List<String> findings) {
    String expected = normalise(expectedBodies.get(function));
    String folded = actual.replace("\r\n", "\n");
    if (folded.indexOf('\r') >= 0) {
      findings.add(
          "guard function "
              + function
              + " has a carriage return that is not part of a CRLF line ending in its body");
      return;
    }
    String live = folded.strip();
    if (!live.equals(expected)) {
      findings.add(
          "guard function "
              + function
              + " body differs from the bundled script (length "
              + live.length()
              + ", md5 "
              + md5Prefix(live)
              + "; expected length "
              + expected.length()
              + ", md5 "
              + md5Prefix(expected)
              + ")");
    }
  }

  private static String normalise(String body) {
    return body.replace("\r\n", "\n").strip();
  }

  /**
   * A catalogue or session value as it may appear in a refusal: every C0 control character, DEL,
   * NEL (U+0085), LINE SEPARATOR (U+2028), PARAGRAPH SEPARATOR (U+2029) and the backslash itself
   * replaced by a backslash, {@code u} and four hex digits, so no name can break the message into a
   * forged log line (CP34-3) and an escape in the output is never ambiguous.
   */
  static String display(String value) {
    if (value == null) {
      return "(null)";
    }
    StringBuilder out = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch < 0x20 || ch == 0x7F || ch == 0x85 || ch == 0x2028 || ch == 0x2029 || ch == '\\') {
        out.append(String.format("\\u%04X", (int) ch));
      } else {
        out.append(ch);
      }
    }
    return out.toString();
  }

  static String md5Prefix(String text) {
    try {
      byte[] d = MessageDigest.getInstance("MD5").digest(text.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(d).substring(0, 12);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("MD5 is a mandatory JDK algorithm", e);
    }
  }

  private static void rules(Connection c, String schema, List<String> findings)
      throws SQLException {
    try (PreparedStatement ps =
            scoped(
                c,
                "SELECT c.relname, r.rulename FROM pg_catalog.pg_rewrite r"
                    + " JOIN pg_catalog.pg_class c ON c.oid = r.ev_class"
                    + " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                    + " WHERE n.nspname = ? AND c.relname IN "
                    + IN_FOUR
                    + " ORDER BY 1, 2",
                schema,
                1);
        ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        findings.add(
            "rule "
                + display(rs.getString(2))
                + " exists on "
                + display(schema)
                + "."
                + display(rs.getString(1)));
      }
    }
    try (PreparedStatement ps =
            scoped(
                c,
                "SELECT c.relname FROM pg_catalog.pg_class c"
                    + " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                    + " WHERE n.nspname = ? AND c.relname IN "
                    + IN_FOUR
                    + " AND c.relhasrules AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite r"
                    + " WHERE r.ev_class = c.oid)",
                schema,
                1);
        ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        findings.add(display(schema) + "." + display(rs.getString(1)) + " is flagged relhasrules");
      }
    }
  }

  private static void policies(Connection c, String schema, List<String> findings)
      throws SQLException {
    try (PreparedStatement ps =
            scoped(
                c,
                "SELECT c.relname, p.polname FROM pg_catalog.pg_policy p"
                    + " JOIN pg_catalog.pg_class c ON c.oid = p.polrelid"
                    + " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                    + " WHERE n.nspname = ? AND c.relname IN "
                    + IN_FOUR
                    + " ORDER BY 1, 2",
                schema,
                1);
        ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        findings.add(
            "row level security policy "
                + display(rs.getString(2))
                + " exists on "
                + display(schema)
                + "."
                + display(rs.getString(1)));
      }
    }
  }

  private static void inheritance(Connection c, String schema, List<String> findings)
      throws SQLException {
    try (PreparedStatement ps =
            scoped(
                c,
                "SELECT pn.nspname, pc.relname, cn.nspname, cc.relname"
                    + " FROM pg_catalog.pg_inherits i"
                    + " JOIN pg_catalog.pg_class pc ON pc.oid = i.inhparent"
                    + " JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace"
                    + " JOIN pg_catalog.pg_class cc ON cc.oid = i.inhrelid"
                    + " JOIN pg_catalog.pg_namespace cn ON cn.oid = cc.relnamespace"
                    + " WHERE (pn.nspname = ? AND pc.relname IN "
                    + IN_FOUR
                    + ") OR (cn.nspname = ? AND cc.relname IN "
                    + IN_FOUR
                    + ") ORDER BY 1, 2, 3, 4",
                schema,
                2);
        ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        findings.add(
            "inheritance edge: "
                + display(rs.getString(3))
                + "."
                + display(rs.getString(4))
                + " inherits from "
                + display(rs.getString(1))
                + "."
                + display(rs.getString(2)));
      }
    }
  }
}
