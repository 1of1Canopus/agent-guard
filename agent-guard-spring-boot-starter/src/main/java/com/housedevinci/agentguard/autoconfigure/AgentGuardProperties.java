package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.application.UnregisteredToolBehaviour;
import com.housedevinci.agentguard.domain.ArgumentRedactor;
import com.housedevinci.agentguard.domain.BudgetKind;
import com.housedevinci.agentguard.domain.BudgetScope;
import com.housedevinci.agentguard.domain.SideEffect;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** {@code agentguard.*} configuration. Everything is off until {@code agentguard.enabled=true}. */
@ConfigurationProperties(prefix = "agentguard")
@Validated
public class AgentGuardProperties {

  /** Master switch. Off by default: nothing is intercepted until you opt in. */
  private boolean enabled = false;

  /** Where decisions and audit rows live. JDBC (PostgreSQL) needs a DataSource bean. */
  @NotNull private StoreType store = StoreType.JDBC;

  /**
   * Fail startup when a tool that carries @ToolPolicy is not reachable through a guarded path, and
   * deny calls whose configured budget scope has no subject. Off = warn instead.
   */
  private boolean strict = true;

  @Valid private final Policy policy = new Policy();
  @Valid private final Approval approval = new Approval();
  @Valid private final Jdbc jdbc = new Jdbc();
  @Valid private final Redis redis = new Redis();
  @Valid private final Budgets budgets = new Budgets();
  @Valid private final Redaction redaction = new Redaction();
  @Valid private final Endpoints endpoints = new Endpoints();
  @Valid private final Audit audit = new Audit();
  @Valid private final Errors errors = new Errors();

  public static class Audit {
    /**
     * HMAC-SHA256 key (at least 32 bytes) for the audit chain: rewrites by anyone without the key
     * become detectable. Required by default (a trail is keyed from row 1 or unkeyed forever, and
     * unkeyed-by-accident is the wrong default for an audit trail); provide it from an environment
     * variable — generate one with {@code openssl rand -base64 32}. Changing it breaks verification
     * of older rows; see {@code agentguard.audit.unkeyed} for the explicit local-dev opt-out.
     */
    private String hmacSecret;

    /**
     * Id of the key above, baked into every row's hashed material from row 1 (see {@code
     * AuditChain}) so rotation is data, not a chain-format change. Defaults {@code k1}; give the
     * next key a different id when rotating (e.g. {@code k2}) and add the old one to {@code
     * agentguard.audit.hmac-keys} so the verifier can still check rows it signed.
     */
    private String hmacKeyId = "k1";

    /**
     * Retired keys the verifier must still accept, by id — {@code
     * agentguard.audit.hmac-keys.k1=...} — so historical rows signed under an id other than the
     * current {@code hmac-key-id} still verify after a rotation. Not used for appending (only
     * {@code hmac-secret}/{@code hmac-key-id} ever sign a new row); an id present here but equal to
     * {@code hmac-key-id} is redundant, not an error.
     */
    private java.util.Map<String, String> hmacKeys = new java.util.LinkedHashMap<>();

    /**
     * Explicit opt-out, for local development only: start with an unkeyed audit chain instead of
     * requiring {@code agentguard.audit.hmac-secret}. A database writer can then rewrite the trail
     * undetected (no HMAC to break); the module warns about this at every startup, not only the
     * first, so the trade-off does not go unnoticed after whoever set it has moved on.
     */
    private boolean unkeyed = false;

    public String getHmacSecret() {
      return hmacSecret;
    }

    public void setHmacSecret(String v) {
      this.hmacSecret = v;
    }

    public String getHmacKeyId() {
      return hmacKeyId;
    }

    public void setHmacKeyId(String v) {
      this.hmacKeyId = v;
    }

    public java.util.Map<String, String> getHmacKeys() {
      return hmacKeys;
    }

    public void setHmacKeys(java.util.Map<String, String> v) {
      this.hmacKeys = v;
    }

    public boolean isUnkeyed() {
      return unkeyed;
    }

    public void setUnkeyed(boolean v) {
      this.unkeyed = v;
    }
  }

  public static class Errors {
    /** Forward the tool's own exception message to the model (default: class name only). */
    private boolean includeToolMessage = false;

    public boolean isIncludeToolMessage() {
      return includeToolMessage;
    }

    public void setIncludeToolMessage(boolean v) {
      this.includeToolMessage = v;
    }
  }

  public enum StoreType {
    JDBC,
    MEMORY
  }

  public enum MissingSubject {
    /** DENY when agentguard.strict=true, SKIP otherwise. */
    DEFAULT,
    DENY,
    FALLBACK_TO_PRINCIPAL,
    SKIP
  }

  public enum BudgetStoreType {
    /** Same as {@code agentguard.store}. */
    DEFAULT,
    JDBC,
    REDIS,
    MEMORY
  }

  public static class Policy {
    /** What to do with a tool that has neither @ToolPolicy nor a registry entry. */
    @NotNull private UnregisteredToolBehaviour unregisteredTools = UnregisteredToolBehaviour.DENY;

    /** Side effects that park the call for human approval. */
    @NotNull
    private Set<SideEffect> approvalRequiredFor =
        EnumSet.of(SideEffect.WRITE, SideEffect.DESTRUCTIVE);

    public UnregisteredToolBehaviour getUnregisteredTools() {
      return unregisteredTools;
    }

    public void setUnregisteredTools(UnregisteredToolBehaviour v) {
      this.unregisteredTools = v;
    }

    public Set<SideEffect> getApprovalRequiredFor() {
      return approvalRequiredFor;
    }

    public void setApprovalRequiredFor(Set<SideEffect> v) {
      this.approvalRequiredFor = v;
    }
  }

  public static class Approval {
    /** How long a parked call waits before it expires. */
    @NotNull
    @DurationMin(nanos = 1, message = "agentguard.approval.ttl must be positive")
    private Duration ttl = Duration.ofHours(1);

    /** How far back an identical call is matched to an existing decision. Null = same as ttl. */
    @DurationMin(nanos = 1, message = "agentguard.approval.replay-window must be positive")
    private Duration replayWindow;

    /** Let the principal that parked a call approve or reject it (four-eyes off). */
    private boolean allowSelfApproval = false;

    public Duration getReplayWindow() {
      return replayWindow;
    }

    public void setReplayWindow(Duration v) {
      this.replayWindow = v;
    }

    public Duration effectiveReplayWindow() {
      return replayWindow == null ? ttl : replayWindow;
    }

    public boolean isAllowSelfApproval() {
      return allowSelfApproval;
    }

    public void setAllowSelfApproval(boolean v) {
      this.allowSelfApproval = v;
    }

    /** Decisions one principal may have waiting at once; further WRITE calls are refused. */
    @Min(1)
    private int maxPendingPerPrincipal = 20;

    /** Largest arguments (UTF-8 bytes) a parked call may carry. */
    @Min(1)
    private int maxArgumentBytes = 64 * 1024;

    @Valid private final Notifier notifier = new Notifier();

    public int getMaxPendingPerPrincipal() {
      return maxPendingPerPrincipal;
    }

    public void setMaxPendingPerPrincipal(int v) {
      this.maxPendingPerPrincipal = v;
    }

    public int getMaxArgumentBytes() {
      return maxArgumentBytes;
    }

    public void setMaxArgumentBytes(int v) {
      this.maxArgumentBytes = v;
    }

    public Duration getTtl() {
      return ttl;
    }

    public void setTtl(Duration ttl) {
      this.ttl = ttl;
    }

    public Notifier getNotifier() {
      return notifier;
    }
  }

  public static class Notifier {
    /** Log every parked call at WARN. */
    private boolean logEnabled = true;

    /** POST a JSON payload to this URL for every parked call (Slack-compatible, n8n, ...). */
    private URI webhookUrl;

    /** Sent as {@code X-AgentGuard-Token} so the receiver can authenticate the webhook. */
    private String webhookSecret;

    @NotNull
    @DurationMin(
        nanos = 1,
        message = "agentguard.approval.notifier.webhook-timeout must be positive")
    private Duration webhookTimeout = Duration.ofSeconds(5);

    /** Allow a plain http webhook URL (trial only); https or a loopback host otherwise. */
    private boolean webhookAllowInsecure = false;

    /** Also send the static X-AgentGuard-Token header (one release, for old receivers). */
    private boolean webhookLegacyToken = false;

    public boolean isWebhookAllowInsecure() {
      return webhookAllowInsecure;
    }

    public void setWebhookAllowInsecure(boolean v) {
      this.webhookAllowInsecure = v;
    }

    public boolean isWebhookLegacyToken() {
      return webhookLegacyToken;
    }

    public void setWebhookLegacyToken(boolean v) {
      this.webhookLegacyToken = v;
    }

    public boolean isLogEnabled() {
      return logEnabled;
    }

    public void setLogEnabled(boolean v) {
      this.logEnabled = v;
    }

    public URI getWebhookUrl() {
      return webhookUrl;
    }

    public void setWebhookUrl(URI v) {
      this.webhookUrl = v;
    }

    public String getWebhookSecret() {
      return webhookSecret;
    }

    public void setWebhookSecret(String v) {
      this.webhookSecret = v;
    }

    public Duration getWebhookTimeout() {
      return webhookTimeout;
    }

    public void setWebhookTimeout(Duration v) {
      this.webhookTimeout = v;
    }
  }

  public static class Jdbc {
    /** Run the bundled idempotent PostgreSQL schema at startup. */
    private boolean initializeSchema = true;

    public boolean isInitializeSchema() {
      return initializeSchema;
    }

    public void setInitializeSchema(boolean v) {
      this.initializeSchema = v;
    }
  }

  public static class Redis {
    /** Redis URI for the REDIS budget store, e.g. {@code redis://localhost:6379}. */
    private URI uri;

    @Valid private final Pool pool = new Pool();

    public URI getUri() {
      return uri;
    }

    public void setUri(URI uri) {
      this.uri = uri;
    }

    public Pool getPool() {
      return pool;
    }
  }

  /**
   * Jedis connection pool. On JDK 21-23 a virtual thread blocked on the pool's growth lock pins its
   * carrier; with more concurrent tool calls than carriers the JVM deadlocks. The pool is therefore
   * filled at startup ({@code min-idle = max-total}, {@code prepare-pool=true}) so it never grows
   * under load. Size {@code max-total} at or above your peak concurrent tool calls.
   */
  public static class Pool {
    @Min(1)
    private int maxTotal = 8;

    /** Idle connections kept open. Null = same as max-total (never grow under load). */
    @Min(0)
    private Integer minIdle;

    @NotNull
    @DurationMin(nanos = 1, message = "agentguard.redis.pool.max-wait must be positive")
    private Duration maxWait = Duration.ofSeconds(2);

    /** Open all min-idle connections at startup, from a platform thread. */
    private boolean preparePool = true;

    /**
     * On JDK 21-23 run every Redis call on a bounded pool of platform threads, so a virtual-thread
     * caller never reaches the connection pool's growth lock. Ignored on JDK 24+.
     */
    private boolean platformThreads = true;

    /**
     * V5: worker-thread count for the platform-thread pool above, decoupled from {@code max-total}
     * (the Jedis connection pool size). Null defaults to {@code max-total}, matching the module's
     * original behaviour. A caller who wants a small, contended connection pool (to exercise or
     * bound Redis concurrency) and a burst of concurrent virtual-thread callers sets this
     * independently instead of inflating {@code max-total} — the workers simply block on the
     * connection pool the way a virtual thread never should.
     */
    @Min(1)
    private Integer platformThreadCount;

    /**
     * V5: bound of the platform-thread pool's work queue (C7). Null defaults to the effective
     * {@link #effectivePlatformThreadCount()}.
     */
    @Min(1)
    private Integer platformThreadQueueSize;

    public boolean isPlatformThreads() {
      return platformThreads;
    }

    public void setPlatformThreads(boolean v) {
      this.platformThreads = v;
    }

    public int getMaxTotal() {
      return maxTotal;
    }

    public void setMaxTotal(int v) {
      this.maxTotal = v;
    }

    public Integer getPlatformThreadCount() {
      return platformThreadCount;
    }

    public void setPlatformThreadCount(Integer v) {
      this.platformThreadCount = v;
    }

    public Integer getPlatformThreadQueueSize() {
      return platformThreadQueueSize;
    }

    public void setPlatformThreadQueueSize(Integer v) {
      this.platformThreadQueueSize = v;
    }

    public int effectivePlatformThreadCount() {
      return platformThreadCount == null ? maxTotal : platformThreadCount;
    }

    public int effectivePlatformThreadQueueSize() {
      return platformThreadQueueSize == null
          ? effectivePlatformThreadCount()
          : platformThreadQueueSize;
    }

    public Integer getMinIdle() {
      return minIdle;
    }

    public void setMinIdle(Integer v) {
      this.minIdle = v;
    }

    public int effectiveMinIdle() {
      return minIdle == null ? maxTotal : Math.min(minIdle, maxTotal);
    }

    public Duration getMaxWait() {
      return maxWait;
    }

    public void setMaxWait(Duration v) {
      this.maxWait = v;
    }

    public boolean isPreparePool() {
      return preparePool;
    }

    public void setPreparePool(boolean v) {
      this.preparePool = v;
    }
  }

  public static class Budgets {
    /** Counter store for budgets. DEFAULT follows {@code agentguard.store}. */
    @NotNull private BudgetStoreType store = BudgetStoreType.DEFAULT;

    /** Limits, all enforced before dispatch. */
    @Valid private List<Limit> limits = new ArrayList<>();

    /** What a TENANT / CONVERSATION limit does when the call carries no such id. */
    @NotNull private MissingSubject missingSubject = MissingSubject.DEFAULT;

    public MissingSubject getMissingSubject() {
      return missingSubject;
    }

    public void setMissingSubject(MissingSubject v) {
      this.missingSubject = v;
    }

    public BudgetStoreType getStore() {
      return store;
    }

    public void setStore(BudgetStoreType v) {
      this.store = v;
    }

    public List<Limit> getLimits() {
      return limits;
    }

    public void setLimits(List<Limit> limits) {
      this.limits = limits;
    }
  }

  public static class Limit {
    @NotNull private BudgetScope scope = BudgetScope.PRINCIPAL;
    @NotNull private BudgetKind kind = BudgetKind.TOOL_CALLS;

    @NotNull
    @DurationMin(nanos = 1, message = "agentguard.budgets.limits[].window must be positive")
    private Duration window = Duration.ofHours(1);

    @Min(1)
    private long limit = 100;

    public BudgetScope getScope() {
      return scope;
    }

    public void setScope(BudgetScope v) {
      this.scope = v;
    }

    public BudgetKind getKind() {
      return kind;
    }

    public void setKind(BudgetKind v) {
      this.kind = v;
    }

    public Duration getWindow() {
      return window;
    }

    public void setWindow(Duration v) {
      this.window = v;
    }

    public long getLimit() {
      return limit;
    }

    public void setLimit(long v) {
      this.limit = v;
    }
  }

  public static class Redaction {
    /** Argument keys whose values are masked in previews, logs and webhooks. */
    private Set<String> sensitiveKeys = ArgumentRedactor.DEFAULT_SENSITIVE_KEYS;

    @Min(16)
    private int maxPreviewLength = ArgumentRedactor.DEFAULT_MAX_LENGTH;

    public Set<String> getSensitiveKeys() {
      return sensitiveKeys;
    }

    public void setSensitiveKeys(Set<String> v) {
      this.sensitiveKeys = v;
    }

    public int getMaxPreviewLength() {
      return maxPreviewLength;
    }

    public void setMaxPreviewLength(int v) {
      this.maxPreviewLength = v;
    }
  }

  public static class Endpoints {
    /** Expose the approval and audit REST endpoints. Secure them with Spring Security. */
    private boolean enabled = false;

    private String basePath = "/agentguard";

    /**
     * Accept an unauthenticated ("anonymous") approver. Trial only: without Spring Security in
     * front of the endpoints anyone who can reach them approves DESTRUCTIVE calls.
     */
    private boolean allowAnonymous = false;

    /** Approvers only see and decide decisions of their own tenant (when they have one). */
    private boolean tenantScoped = true;

    /**
     * When {@code tenantScoped}, an approver whose {@code TenantResolver} yields no tenant (a
     * missing claim, a service account, a misconfigured resolver) is refused (403) instead of
     * seeing and deciding every tenant's work. Set {@code false} only for a deliberate cross-tenant
     * approver role.
     */
    private boolean requireTenant = true;

    public boolean isTenantScoped() {
      return tenantScoped;
    }

    public void setTenantScoped(boolean v) {
      this.tenantScoped = v;
    }

    public boolean isRequireTenant() {
      return requireTenant;
    }

    public void setRequireTenant(boolean v) {
      this.requireTenant = v;
    }

    public boolean isAllowAnonymous() {
      return allowAnonymous;
    }

    public void setAllowAnonymous(boolean v) {
      this.allowAnonymous = v;
    }

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean v) {
      this.enabled = v;
    }

    public String getBasePath() {
      return basePath;
    }

    public void setBasePath(String v) {
      this.basePath = v;
    }
  }

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public StoreType getStore() {
    return store;
  }

  public boolean isStrict() {
    return strict;
  }

  public void setStrict(boolean strict) {
    this.strict = strict;
  }

  public void setStore(StoreType store) {
    this.store = store;
  }

  public Policy getPolicy() {
    return policy;
  }

  public Approval getApproval() {
    return approval;
  }

  public Jdbc getJdbc() {
    return jdbc;
  }

  public Redis getRedis() {
    return redis;
  }

  public Budgets getBudgets() {
    return budgets;
  }

  public Redaction getRedaction() {
    return redaction;
  }

  public Endpoints getEndpoints() {
    return endpoints;
  }

  public Audit getAudit() {
    return audit;
  }

  public Errors getErrors() {
    return errors;
  }
}
