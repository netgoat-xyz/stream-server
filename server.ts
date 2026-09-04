#!/usr/bin/env bun
import { timingSafeEqual } from "node:crypto";
import mongoose from "mongoose";
import DomainModel from "./models/Domain";
import ProxyConfigModel from "./models/ProxyConfig";
import SettingsModel from "./models/Settings";
import UserModel from "./models/User";
import WAFRuleModel from "./models/WAFRule";

interface RouteCachePolicy {
  enabled?: boolean;
  ttl_seconds?: number;
  max_entries?: number;
  max_body_bytes?: number;
}

interface RouteBandwidthPolicy {
  enabled?: boolean;
  bytes_per_second?: number;
  burst_bytes?: number;
  key?: AgentKeyMode;
}

/** Agent-facing per-route overrides (`policy.RoutePolicy`). Empty objects are omitted. */
export interface RoutePolicy {
  cache?: RouteCachePolicy;
  bandwidth?: RouteBandwidthPolicy;
}

interface Subdomain {
  id: string;
  subdomain: string;
  full_domain: string;
  target_url: string;
  target_urls?: string[];
  certificate_pem?: string;
  private_key_pem?: string;
  policy?: RoutePolicy;
  active: boolean;
}

interface Domain {
  id: string;
  domain: string;
  target_url: string;
  target_urls?: string[];
  certificate_pem?: string;
  private_key_pem?: string;
  policy?: RoutePolicy;
  team_id?: string;
  active: boolean;
  subdomains: Subdomain[];
}

interface WafRule {
  id: string;
  name: string;
  expression: string;
  action: string;
  priority: number;
  proxy_config_id?: string;
  hosts?: string[];
}

interface User {
  id: string;
  username: string;
  email?: string;
  role?: string;
}

type AgentKeyMode = "ip" | "host" | "route" | "global";

interface AgentToggle {
  enabled: boolean;
}

interface AgentModelConfig extends AgentToggle {
  threshold: number;
  model_path: string;
  scaler_path: string;
  python_script: string;
  feature_header: string;
}

interface AgentConfig {
  cache: AgentToggle & {
    ttl_seconds: number;
    max_entries: number;
    max_body_bytes: number;
  };
  rate_limit: AgentToggle & {
    requests_per_minute: number;
    burst: number;
    key: AgentKeyMode;
  };
  request_queue: AgentToggle & {
    max_concurrent: number;
    max_queued: number;
    timeout_seconds: number;
  };
  bandwidth: AgentToggle & {
    bytes_per_second: number;
    burst_bytes: number;
    key: AgentKeyMode;
  };
  metrics: AgentToggle & {
    path: string;
  };
  koda_waf: AgentModelConfig;
  koda_2: AgentModelConfig;
}

type AgentConfigInput = Partial<Record<keyof AgentConfig, Record<string, unknown>>>;

interface DomainsResponse {
  domains: Domain[];
  waf_rules: WafRule[];
  zero_trust_enabled: boolean;
  agent_config: AgentConfig;
}

export interface CachedState {
  domains: Domain[];
  waf_rules: WafRule[];
  users: User[];
  zero_trust_enabled: boolean;
  agent_config: AgentConfig;
  last_pulled: Date;
}

function boundedInteger(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

const PORT = boundedInteger(process.env.PORT, 8787, 1, 65535);
const HOST = process.env.HOST || "0.0.0.0";
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017";
const MONGODB_DB = process.env.MONGODB_DB || "netgoat";
const API_KEY = process.env.API_KEY || "";
const DIAMOND_KEY = process.env.DIAMOND_KEY || "";
const CONFIG_WRITE_KEY = process.env.CONFIG_WRITE_KEY || "";
const ALLOW_UNAUTHENTICATED = process.env.ALLOW_UNAUTHENTICATED === "true";
const POLL_INTERVAL = boundedInteger(process.env.POLL_INTERVAL, 5000, 250, 3600000);
const MONGO_RETRY_INTERVAL = boundedInteger(process.env.MONGO_RETRY_INTERVAL, 10000, 1000, 3600000);
const SEED_FILE = process.env.SEED_FILE || "./seed-data.json";
const LOG_LEVEL = process.env.LOG_LEVEL || "info";
const MAX_CONFIG_BODY_BYTES = 64 * 1024;
const MAX_SEED_FILE_BYTES = 10 * 1024 * 1024;

const defaultAgentConfig: AgentConfig = {
  cache: {
    enabled: false,
    ttl_seconds: 60,
    max_entries: 1024,
    max_body_bytes: 1048576,
  },
  rate_limit: {
    enabled: false,
    requests_per_minute: 60,
    burst: 60,
    key: "ip",
  },
  request_queue: {
    enabled: false,
    max_concurrent: 10,
    max_queued: 100,
    timeout_seconds: 5,
  },
  bandwidth: {
    enabled: false,
    bytes_per_second: 1048576,
    burst_bytes: 1048576,
    key: "ip",
  },
  metrics: {
    enabled: false,
    path: "/__netgoat/metrics",
  },
  koda_waf: {
    enabled: false,
    threshold: 0.7,
    model_path: "ai/smart_waf_model.pkl",
    scaler_path: "ai/model_features.pkl",
    python_script: "ai/koda_waf_server.py",
    feature_header: "X-KodaWaf-Features",
  },
  koda_2: {
    enabled: false,
    threshold: 0.7,
    model_path: "ai/koda2.keras",
    scaler_path: "ai/koda2_scaler.pkl",
    python_script: "ai/koda2_server.py",
    feature_header: "X-Koda2-Features",
  },
};

const LOG = {
  levels: { debug: 0, info: 1, warn: 2, error: 3 } as Record<string, number>,
  current: (LOG_LEVEL in { debug: 1, info: 1, warn: 1, error: 1 }) ? LOG_LEVEL : "info",
  colors: {
    reset: "\x1b[0m",
    dim: "\x1b[2m",
    bold: "\x1b[1m",
    debug: "\x1b[36m",
    info: "\x1b[32m",
    warn: "\x1b[33m",
    error: "\x1b[31m",
    service: "\x1b[35m",
  } as Record<string, string>,

  color(level: string, value: string) {
    if (process.env.NO_COLOR) return value;
    const color = this.colors[level] || "";
    return `${color}${value}${this.colors.reset}`;
  },

  log(level: string, msg: string, ...args: unknown[]) {
    if ((this.levels[level] ?? 99) < (this.levels[this.current] ?? 1)) return;
    const ts = new Date().toISOString().slice(11, 19);
    const prefix = [
      this.color("dim", ts),
      this.color("service", "stream"),
      this.color(level, level.toUpperCase().padEnd(5)),
      this.color("bold", msg),
    ].join(" ");
    if (args.length > 0) {
      console[level === "error" ? "error" : level === "warn" ? "warn" : "log"](
        prefix, ...args
      );
    } else {
      console[level === "error" ? "error" : level === "warn" ? "warn" : "log"](
        prefix
      );
    }
  },

  debug(msg: string, ...args: unknown[]) { this.log("debug", msg, ...args); },
  info(msg: string, ...args: unknown[]) { this.log("info", msg, ...args); },
  warn(msg: string, ...args: unknown[]) { this.log("warn", msg, ...args); },
  error(msg: string, ...args: unknown[]) { this.log("error", msg, ...args); },
};

function cloneDefaultAgentConfig(): AgentConfig {
  return JSON.parse(JSON.stringify(defaultAgentConfig));
}

function boolValue(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

function clampFloat(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, min), max);
}

function keyMode(value: unknown, fallback: AgentKeyMode): AgentKeyMode {
  return value === "ip" || value === "host" || value === "route" || value === "global"
    ? value
    : fallback;
}

function safePath(value: unknown, fallback: string, maxLength = 256): string {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength || /[\u0000-\u001f\u007f]/.test(trimmed)) return fallback;
  return trimmed;
}

function safeMetricsPath(value: unknown, fallback: string): string {
  const path = safePath(value, fallback);
  return path.startsWith("/") && !path.includes("?") && !path.includes("#") ? path : fallback;
}

function safeHeader(value: unknown, fallback: string): string {
  const header = safePath(value, fallback, 128);
  return /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(header) ? header : fallback;
}

export function normalizeAgentConfig(input: unknown): AgentConfig {
  const base = cloneDefaultAgentConfig();
  const raw: AgentConfigInput = input && typeof input === "object" ? input as AgentConfigInput : {};

  return {
    cache: {
      enabled: boolValue(raw.cache?.enabled, base.cache.enabled),
      ttl_seconds: clampInt(raw.cache?.ttl_seconds, base.cache.ttl_seconds, 1, 86400),
      max_entries: clampInt(raw.cache?.max_entries, base.cache.max_entries, 1, 100000),
      max_body_bytes: clampInt(raw.cache?.max_body_bytes, base.cache.max_body_bytes, 1024, 104857600),
    },
    rate_limit: {
      enabled: boolValue(raw.rate_limit?.enabled, base.rate_limit.enabled),
      requests_per_minute: clampInt(raw.rate_limit?.requests_per_minute, base.rate_limit.requests_per_minute, 1, 1000000),
      burst: clampInt(raw.rate_limit?.burst, base.rate_limit.burst, 1, 1000000),
      key: keyMode(raw.rate_limit?.key, base.rate_limit.key),
    },
    request_queue: {
      enabled: boolValue(raw.request_queue?.enabled, base.request_queue.enabled),
      max_concurrent: clampInt(raw.request_queue?.max_concurrent, base.request_queue.max_concurrent, 1, 10000),
      max_queued: clampInt(raw.request_queue?.max_queued, base.request_queue.max_queued, 0, 100000),
      timeout_seconds: clampInt(raw.request_queue?.timeout_seconds, base.request_queue.timeout_seconds, 1, 600),
    },
    bandwidth: {
      enabled: boolValue(raw.bandwidth?.enabled, base.bandwidth.enabled),
      bytes_per_second: clampInt(raw.bandwidth?.bytes_per_second, base.bandwidth.bytes_per_second, 1024, 10737418240),
      burst_bytes: clampInt(raw.bandwidth?.burst_bytes, base.bandwidth.burst_bytes, 1024, 10737418240),
      key: keyMode(raw.bandwidth?.key, base.bandwidth.key),
    },
    metrics: {
      enabled: boolValue(raw.metrics?.enabled, base.metrics.enabled),
      path: safeMetricsPath(raw.metrics?.path, base.metrics.path),
    },
    koda_waf: {
      enabled: boolValue(raw.koda_waf?.enabled, base.koda_waf.enabled),
      threshold: clampFloat(raw.koda_waf?.threshold, base.koda_waf.threshold, 0.01, 1),
      model_path: safePath(raw.koda_waf?.model_path, base.koda_waf.model_path),
      scaler_path: safePath(raw.koda_waf?.scaler_path, base.koda_waf.scaler_path),
      python_script: safePath(raw.koda_waf?.python_script, base.koda_waf.python_script),
      feature_header: safeHeader(raw.koda_waf?.feature_header, base.koda_waf.feature_header),
    },
    koda_2: {
      enabled: boolValue(raw.koda_2?.enabled, base.koda_2.enabled),
      threshold: clampFloat(raw.koda_2?.threshold, base.koda_2.threshold, 0.01, 1),
      model_path: safePath(raw.koda_2?.model_path, base.koda_2.model_path),
      scaler_path: safePath(raw.koda_2?.scaler_path, base.koda_2.scaler_path),
      python_script: safePath(raw.koda_2?.python_script, base.koda_2.python_script),
      feature_header: safeHeader(raw.koda_2?.feature_header, base.koda_2.feature_header),
    },
  };
}

export function redactMongoUri(uri: string): string {
  try {
    const parsed = new URL(uri);
    if (parsed.username) parsed.username = "***";
    if (parsed.password) parsed.password = "***";
    return parsed.toString();
  } catch {
    return uri.replace(/(mongodb(?:\+srv)?:\/\/)[^/@\s]*@/gi, "$1***@");
  }
}

function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replaceAll(MONGODB_URI, redactMongoUri(MONGODB_URI))
    .replace(/(mongodb(?:\+srv)?:\/\/)[^/@\s]*@/gi, "$1***@");
}

let connected = mongoose.connection.readyState === 1;
let mongoConnectPromise: Promise<boolean> | null = null;
let nextMongoConnectAt = 0;

mongoose.connection.on("connected", () => {
  connected = true;
});
mongoose.connection.on("disconnected", () => {
  if (connected) LOG.warn("MongoDB connection lost; cached configuration remains active");
  connected = false;
});
mongoose.connection.on("error", (error) => {
  const wasConnected = connected;
  connected = false;
  if (wasConnected) LOG.warn(`MongoDB connection error: ${errorMessage(error)}`);
});

async function ensureMongoConnection(force = false): Promise<boolean> {
  if (connected && mongoose.connection.readyState === 1) return true;
  if (mongoConnectPromise) return mongoConnectPromise;
  if (!force && Date.now() < nextMongoConnectAt) return false;

  nextMongoConnectAt = Date.now() + MONGO_RETRY_INTERVAL;
  mongoConnectPromise = (async () => {
    try {
      await mongoose.connect(MONGODB_URI, {
        serverSelectionTimeoutMS: 5000,
        connectTimeoutMS: 5000,
        dbName: MONGODB_DB,
        maxPoolSize: 10,
        autoIndex: false,
      });
      await mongoose.connection.db!.command({ ping: 1 });
      connected = true;
      nextMongoConnectAt = 0;
      LOG.info(`Connected to MongoDB at ${redactMongoUri(MONGODB_URI)}`);
      return true;
    } catch (error) {
      connected = false;
      LOG.warn(`MongoDB unavailable; using cached configuration: ${errorMessage(error)}`);
      return false;
    } finally {
      mongoConnectPromise = null;
    }
  })();

  return mongoConnectPromise;
}

// ── Data loader — pulls from MongoDB or seed JSON ──────────────────

let cachedState: CachedState = {
  domains: [],
  waf_rules: [],
  users: [],
  zero_trust_enabled: false,
  agent_config: cloneDefaultAgentConfig(),
  last_pulled: new Date(0),
};

interface CachedResponseBodies {
  domains: string;
  users: string;
  agentConfig: string;
}

function serializeCachedResponses(state: CachedState): CachedResponseBodies {
  const domains: DomainsResponse = {
    domains: state.domains,
    waf_rules: state.waf_rules,
    zero_trust_enabled: state.zero_trust_enabled,
    agent_config: state.agent_config,
  };
  return {
    domains: JSON.stringify(domains),
    users: JSON.stringify({ users: state.users }),
    agentConfig: JSON.stringify({ agent_config: state.agent_config }),
  };
}

let cachedResponseBodies = serializeCachedResponses(cachedState);

function replaceCachedState(state: CachedState): void {
  cachedState = state;
  cachedResponseBodies = serializeCachedResponses(state);
}

async function loadSeedData(): Promise<CachedState> {
  try {
    const file = Bun.file(SEED_FILE);
    const exists = await file.exists();
    if (!exists) {
      LOG.warn(`Seed file ${SEED_FILE} not found, using empty state`);
      return emptyState();
    }
    if (file.size > MAX_SEED_FILE_BYTES) {
      throw new Error(`seed file exceeds ${MAX_SEED_FILE_BYTES} bytes`);
    }
    const parsed = asRecord(JSON.parse(await file.text()));
    LOG.info(`Loaded seed data from ${SEED_FILE}`);
    return buildCachedState({
      domainDocs: Array.isArray(parsed.domains) ? parsed.domains : [],
      proxyConfigDocs: [],
      globalRuleDocs: Array.isArray(parsed.waf_rules) ? parsed.waf_rules : [],
      userDocs: Array.isArray(parsed.users) ? parsed.users : [],
      settingsDoc: {
        zeroTrustEnabled: parsed.zero_trust_enabled === true,
        agentConfig: parsed.agent_config,
      },
    });
  } catch (err) {
    LOG.warn(`Failed to load seed file ${SEED_FILE}: ${errorMessage(err)}`);
    return emptyState();
  }
}

function emptyState(): CachedState {
  return {
    domains: [],
    waf_rules: [],
    users: [],
    zero_trust_enabled: false,
    agent_config: cloneDefaultAgentConfig(),
    last_pulled: new Date(),
  };
}

type PlainRecord = Record<string, unknown>;

interface MongoStateDocuments {
  domainDocs: readonly unknown[];
  proxyConfigDocs: readonly unknown[];
  globalRuleDocs: readonly unknown[];
  userDocs: readonly unknown[];
  settingsDoc: unknown;
  legacyZeroTrustDoc?: unknown;
}

function asRecord(value: unknown): PlainRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as PlainRecord
    : {};
}

function records(value: unknown): PlainRecord[] {
  return Array.isArray(value) ? value.map(asRecord) : [];
}

function textValue(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function idValue(value: unknown, fallback = ""): string {
  if (value === null || value === undefined) return fallback;
  const id = String(value).trim();
  return id || fallback;
}

function routeKey(domainId: string, subdomain: string): string {
  return `${domainId}\0${subdomain.toLowerCase()}`;
}

function uniqueTargets(value: unknown, primary = ""): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const target of Array.isArray(value) ? value : []) {
    const candidate = textValue(target);
    if (!candidate || candidate === primary || seen.has(candidate)) continue;
    seen.add(candidate);
    result.push(candidate);
  }
  return result;
}

function optionalBool(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function optionalBoundedInt(value: unknown, min: number, max: number): number | undefined {
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isInteger(n) || n < min || n > max) return undefined;
  return n;
}

function optionalKeyMode(value: unknown): AgentKeyMode | undefined {
  return value === "ip" || value === "host" || value === "route" || value === "global"
    ? value
    : undefined;
}

function definedEntries<T extends Record<string, unknown>>(value: T): T | undefined {
  const entries = Object.entries(value).filter(([, entry]) => entry !== undefined);
  if (entries.length === 0) return undefined;
  return Object.fromEntries(entries) as T;
}

/**
 * Maps Mongo `route_policy` (or seed/agent `policy`) onto the Go agent contract.
 * Unknown keys are dropped. Invalid bandwidth keys and out-of-range numbers are
 * dropped (not clamped) so `policy.RoutePolicy.Validate()` cannot reject the
 * whole snapshot. Empty objects are omitted.
 */
export function normalizeRoutePolicy(input: unknown): RoutePolicy | undefined {
  if (input === null || input === undefined || typeof input !== "object" || Array.isArray(input)) {
    return undefined;
  }
  const raw = input as PlainRecord;
  const policy: RoutePolicy = {};

  if (raw.cache !== null && typeof raw.cache === "object" && !Array.isArray(raw.cache)) {
    const cacheRaw = raw.cache as PlainRecord;
    const cache = definedEntries({
      enabled: optionalBool(cacheRaw.enabled),
      ttl_seconds: optionalBoundedInt(cacheRaw.ttl_seconds, 1, 86400),
      max_entries: optionalBoundedInt(cacheRaw.max_entries, 1, 100000),
      max_body_bytes: optionalBoundedInt(cacheRaw.max_body_bytes, 1024, 104857600),
    });
    if (cache) policy.cache = cache;
  }

  if (raw.bandwidth !== null && typeof raw.bandwidth === "object" && !Array.isArray(raw.bandwidth)) {
    const bandwidthRaw = raw.bandwidth as PlainRecord;
    const bandwidth = definedEntries({
      enabled: optionalBool(bandwidthRaw.enabled),
      bytes_per_second: optionalBoundedInt(bandwidthRaw.bytes_per_second, 1024, 10737418240),
      burst_bytes: optionalBoundedInt(bandwidthRaw.burst_bytes, 1024, 10737418240),
      key: optionalKeyMode(bandwidthRaw.key),
    });
    if (bandwidth) policy.bandwidth = bandwidth;
  }

  return policy.cache || policy.bandwidth ? policy : undefined;
}

function routePolicyFromDoc(doc: PlainRecord): RoutePolicy | undefined {
  return normalizeRoutePolicy(doc.route_policy ?? doc.policy);
}

function optionalPem(value: unknown): string | undefined {
  const pem = textValue(value);
  return pem || undefined;
}

/** Converts projected MongoDB documents into the public, agent-facing snapshot. */
export function buildCachedState(documents: MongoStateDocuments): CachedState {
  const hostsByScope = new Map<string, string[]>();
  for (const rawDomain of documents.domainDocs) {
    const doc = asRecord(rawDomain);
    if (doc.active === false) continue;
    const domain = textValue(doc.domain).toLowerCase();
    if (!domain) continue;
    const domainId = idValue(doc._id, idValue(doc.id, domain));
    const hosts = [domain];
    for (const rawSubdomain of records(doc.subdomains)) {
      if (rawSubdomain.active === false) continue;
      const subdomain = textValue(rawSubdomain.subdomain).toLowerCase();
      const fullDomain = (textValue(rawSubdomain.full_domain) || (subdomain ? `${subdomain}.${domain}` : ""))
        .toLowerCase();
      if (fullDomain) hosts.push(fullDomain);
    }
    hostsByScope.set(domainId, [...new Set(hosts)]);
  }

  const upstreamsByRoute = new Map<string, string[]>();
  for (const rawConfig of documents.proxyConfigDocs) {
    const config = asRecord(rawConfig);
    if (config.enabled === false) continue;
    const domainId = idValue(config.domain_id);
    if (!domainId) continue;
    const urls = records(config.upstream_servers)
      .filter((server) => server.down !== true)
      .map((server) => textValue(server.url))
      .filter(Boolean);
    const key = routeKey(domainId, textValue(config.subdomain));
    upstreamsByRoute.set(key, uniqueTargets([...(upstreamsByRoute.get(key) || []), ...urls]));
    const configId = idValue(config._id, idValue(config.id));
    const domainHosts = hostsByScope.get(domainId);
    if (configId && domainHosts?.length) {
      const subdomain = textValue(config.subdomain).toLowerCase();
      const scopedHost = subdomain ? `${subdomain}.${domainHosts[0]}` : domainHosts[0];
      hostsByScope.set(configId, [scopedHost]);
    }
  }

  const domains: Domain[] = [];
  const wafRules: WafRule[] = [];
  for (const rawDomain of documents.domainDocs) {
    const doc = asRecord(rawDomain);
    if (doc.active === false) continue;
    const domain = textValue(doc.domain).toLowerCase();
    if (!domain) continue;
    const domainId = idValue(doc._id, idValue(doc.id, domain));
    const targetUrl = textValue(doc.target_url);
    const targetUrls = uniqueTargets(upstreamsByRoute.get(routeKey(domainId, "")), targetUrl);

    const subdomains: Subdomain[] = [];
    for (const rawSubdomain of records(doc.subdomains)) {
      if (rawSubdomain.active === false) continue;
      const subdomain = textValue(rawSubdomain.subdomain).toLowerCase();
      const fullDomain = (textValue(rawSubdomain.full_domain) || (subdomain ? `${subdomain}.${domain}` : ""))
        .toLowerCase();
      if (!fullDomain) continue;
      const subdomainTarget = textValue(rawSubdomain.target_url);
      subdomains.push({
        id: idValue(rawSubdomain._id, idValue(rawSubdomain.id, fullDomain)),
        subdomain,
        full_domain: fullDomain,
        target_url: subdomainTarget,
        target_urls: uniqueTargets(upstreamsByRoute.get(routeKey(domainId, subdomain)), subdomainTarget),
        certificate_pem: optionalPem(rawSubdomain.certificate_pem),
        private_key_pem: optionalPem(rawSubdomain.private_key_pem),
        policy: routePolicyFromDoc(rawSubdomain),
        active: true,
      });
    }

    domains.push({
      id: domainId,
      domain,
      target_url: targetUrl,
      target_urls: targetUrls,
      certificate_pem: textValue(doc.certificate_pem),
      private_key_pem: textValue(doc.private_key_pem),
      policy: routePolicyFromDoc(doc),
      team_id: idValue(doc.team_id),
      active: true,
      subdomains,
    });

    for (const rule of records(doc.waf_rules)) {
      const normalized = normalizeWafRule(rule, domainId, hostsByScope.get(domainId));
      if (normalized) wafRules.push(normalized);
    }
  }

  for (const rawRule of documents.globalRuleDocs) {
    const rule = asRecord(rawRule);
    const scopeId = idValue(rule.proxy_config_id);
    const normalized = normalizeWafRule(rule, scopeId, scopeId ? hostsByScope.get(scopeId) : undefined);
    if (normalized) wafRules.push(normalized);
  }
  wafRules.sort((left, right) => right.priority - left.priority || left.name.localeCompare(right.name));

  const users: User[] = [];
  for (const rawUser of documents.userDocs) {
    const doc = asRecord(rawUser);
    if (doc.banned === true) continue;
    const email = textValue(doc.email).toLowerCase();
    const username = textValue(doc.name) || textValue(doc.username) || email.split("@")[0] || "";
    if (!username) continue;
    users.push({
      id: idValue(doc._id, idValue(doc.id, username)),
      username,
      email,
      role: textValue(doc.role) || "user",
    });
  }

  const settings = asRecord(documents.settingsDoc);
  const legacyZeroTrust = asRecord(documents.legacyZeroTrustDoc).value;
  const zeroTrustEnabled = typeof settings.zeroTrustEnabled === "boolean"
    ? settings.zeroTrustEnabled
    : legacyZeroTrust === true || legacyZeroTrust === "true";

  return {
    domains,
    waf_rules: wafRules,
    users,
    zero_trust_enabled: zeroTrustEnabled,
    agent_config: normalizeAgentConfig(settings.agentConfig),
    last_pulled: new Date(),
  };
}

function normalizeWafRule(rule: PlainRecord, scopeId: string, scopeHosts?: string[]): WafRule | null {
  if (rule.enabled === false) return null;
  const name = textValue(rule.name);
  const expression = textValue(rule.expression);
  if (!name || !expression) return null;
  if (scopeId && (!scopeHosts || scopeHosts.length === 0)) return null;
  const rawAction = textValue(rule.action).toUpperCase();
  const action = rawAction === "ALLOW" || rawAction === "LOG" || rawAction === "BLOCK"
    ? rawAction
    : "BLOCK";
  const rawPriority = Number(rule.priority);
  return {
    id: idValue(rule._id, idValue(rule.id, name)),
    name,
    expression,
    action,
    priority: Number.isFinite(rawPriority) ? Math.trunc(rawPriority) : 0,
    proxy_config_id: scopeId,
    hosts: scopeId ? [...(scopeHosts || [])] : undefined,
  };
}

async function pullFromMongo(): Promise<CachedState | null> {
  try {
    const [domainDocs, proxyConfigDocs, globalRuleDocs, userDocs, settingsDoc, legacyZeroTrustDoc] =
      await Promise.all([
        DomainModel.find({ active: { $ne: false } })
          .select("_id domain target_url certificate_pem private_key_pem team_id active subdomains waf_rules route_policy")
          .sort({ domain: 1 })
          .lean(),
        ProxyConfigModel.find({ enabled: { $ne: false } })
          .select("_id domain_id subdomain upstream_servers enabled")
          .lean(),
        WAFRuleModel.find({ enabled: { $ne: false } })
          .select("_id name expression action priority proxy_config_id enabled")
          .sort({ priority: -1, name: 1 })
          .lean(),
        UserModel.find({ banned: { $ne: true } })
          .select("_id name email role banned")
          .sort({ name: 1, email: 1 })
          .lean(),
        SettingsModel.findOne({
          $or: [
            { agentConfig: { $exists: true } },
            { zeroTrustEnabled: { $exists: true } },
          ],
        })
          .select("agentConfig zeroTrustEnabled updatedAt")
          .sort({ updatedAt: -1, _id: -1 })
          .lean(),
        SettingsModel.collection.findOne(
          { key: "zero_trust_enabled" },
          { projection: { value: 1 } },
        ),
      ]);

    const nextState = buildCachedState({
      domainDocs,
      proxyConfigDocs,
      globalRuleDocs,
      userDocs,
      settingsDoc,
      legacyZeroTrustDoc,
    });

    LOG.info(
      `Pulled from MongoDB: ${nextState.domains.length} domains, ${nextState.waf_rules.length} rules, ${nextState.users.length} users`
    );
    return nextState;
  } catch (err) {
    LOG.error(`MongoDB pull failed: ${errorMessage(err)}`);
    return null;
  }
}

// ── State updater ──────────────────────────────────────────────────

let pollingTimer: ReturnType<typeof setTimeout> | null = null;
let pollingPromise: Promise<void> | null = null;
let stateRevision = 0;
let shuttingDown = false;

async function updateState(): Promise<void> {
  if (pollingPromise) return pollingPromise;

  pollingPromise = (async () => {
    LOG.debug("Polling for config updates...");
    const revisionAtStart = stateRevision;

    if (await ensureMongoConnection()) {
      const result = await pullFromMongo();
      if (result && revisionAtStart === stateRevision) {
        replaceCachedState(result);
        return;
      }
      if (result) LOG.debug("Discarded a stale poll that raced with a config update");
    }

    if (cachedState.domains.length === 0 && cachedState.last_pulled.getTime() === 0) {
      replaceCachedState(await loadSeedData());
    }
  })().finally(() => {
    pollingPromise = null;
  });

  return pollingPromise;
}

function schedulePoll(delay: number): void {
  if (shuttingDown) return;
  pollingTimer = setTimeout(() => {
    void updateState().finally(() => schedulePoll(POLL_INTERVAL));
  }, delay);
}

// ── Auth middleware ────────────────────────────────────────────────

function requestKeys(request: Request): string[] {
  return [
    request.headers.get("X-API-Key") || "",
    (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, ""),
    request.headers.get("X-Diamond-Key") || "",
    request.headers.get("X-Zero-Trust-Key") || "",
    request.headers.get("X-Config-Write-Key") || "",
  ].filter(Boolean);
}

function matchesKey(request: Request, configuredKeys: string[]): boolean {
  const presentedKeys = requestKeys(request);
  return presentedKeys.some((presented) => configuredKeys.some((configured) => safeEqual(presented, configured)));
}

function checkAuth(request: Request): boolean {
  const readKeys = [API_KEY, DIAMOND_KEY].filter(Boolean);
  if (readKeys.length === 0) {
    return ALLOW_UNAUTHENTICATED || Boolean(CONFIG_WRITE_KEY && matchesKey(request, [CONFIG_WRITE_KEY]));
  }
  const configuredKeys = CONFIG_WRITE_KEY ? [...readKeys, CONFIG_WRITE_KEY] : readKeys;
  return matchesKey(request, configuredKeys);
}

function checkWriteAuth(request: Request): boolean {
  return CONFIG_WRITE_KEY ? matchesKey(request, [CONFIG_WRITE_KEY]) : checkAuth(request);
}

function safeEqual(a: string, b: string): boolean {
  if (!a || !b) return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function unauthorized(): Response {
  return jsonResponse(
    { error: "unauthorized" },
    401,
    { "WWW-Authenticate": 'Bearer realm="netgoat-stream-server"' },
  );
}

function forbidden(): Response {
  return jsonResponse({ error: "forbidden" }, 403);
}

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function jsonBodyResponse(body: string, status = 200, headers?: HeadersInit): Response {
  return new Response(body, {
    status,
    headers: { ...JSON_HEADERS, ...headers },
  });
}

function jsonResponse(data: unknown, status = 200, headers?: HeadersInit): Response {
  return jsonBodyResponse(JSON.stringify(data), status, headers);
}

function methodNotAllowed(methods: string[]): Response {
  return jsonResponse({ error: "method not allowed" }, 405, { Allow: methods.join(", ") });
}

class RequestError extends Error {
  constructor(readonly status: number, readonly publicMessage: string) {
    super(publicMessage);
  }
}

export async function readJSONBody(request: Request): Promise<unknown> {
  const contentLengthHeader = request.headers.get("content-length");
  if (contentLengthHeader !== null) {
    if (!/^\d+$/.test(contentLengthHeader.trim())) {
      throw new RequestError(400, "invalid content-length");
    }
    if (Number(contentLengthHeader) > MAX_CONFIG_BODY_BYTES) {
      throw new RequestError(413, "request body too large");
    }
  }

  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType && contentType !== "application/json" && !contentType.endsWith("+json")) {
    throw new RequestError(415, "content-type must be application/json");
  }
  if (!request.body) return {};

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_CONFIG_BODY_BYTES) {
        await reader.cancel("request body too large").catch(() => undefined);
        throw new RequestError(413, "request body too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  if (total === 0) return {};
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new RequestError(400, "invalid JSON body");
  }
}

async function saveAgentConfig(agentConfig: AgentConfig): Promise<boolean> {
  let persisted = false;
  if (connected) {
    await SettingsModel.findOneAndUpdate(
      { key: { $exists: false } },
      { $set: { agentConfig } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    persisted = true;
  }

  stateRevision++;
  replaceCachedState({
    ...cachedState,
    agent_config: agentConfig,
    last_pulled: new Date(),
  });
  return persisted;
}

async function routeRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (!checkAuth(request)) return unauthorized();

  switch (path) {
    case "/health":
    case "/": {
      if (request.method !== "GET") return methodNotAllowed(["GET"]);
      return jsonResponse({
        status: "ok",
        service: "netgoat-stream-server",
        version: "1.0.0",
        uptime: process.uptime(),
        mongo: connected,
        domains_cached: cachedState.domains.length,
        rules_cached: cachedState.waf_rules.length,
        users_cached: cachedState.users.length,
        agent_config_cached: true,
        auth_required: Boolean(API_KEY || DIAMOND_KEY) || !ALLOW_UNAUTHENTICATED,
        config_write_key_configured: Boolean(CONFIG_WRITE_KEY),
        last_pulled: cachedState.last_pulled.toISOString(),
      });
    }

    case "/domains": {
      if (request.method !== "GET") {
        return methodNotAllowed(["GET"]);
      }
      return jsonBodyResponse(cachedResponseBodies.domains);
    }

    case "/agent-config": {
      if (request.method === "GET") {
        return jsonBodyResponse(cachedResponseBodies.agentConfig);
      }
      if (request.method !== "PUT") {
        return methodNotAllowed(["GET", "PUT"]);
      }
      if (!checkWriteAuth(request)) return forbidden();
      try {
        const parsedBody = await readJSONBody(request);
        if (parsedBody === null || typeof parsedBody !== "object" || Array.isArray(parsedBody)) {
          throw new RequestError(400, "request body must be a JSON object");
        }
        const body = asRecord(parsedBody);
        const candidate = body.agent_config ?? body;
        if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
          throw new RequestError(400, "agent_config must be an object");
        }
        const agentConfig = normalizeAgentConfig(candidate);
        const persisted = await saveAgentConfig(agentConfig);
        return jsonResponse({ agent_config: cachedState.agent_config, persisted });
      } catch (error) {
        if (error instanceof RequestError) {
          return jsonResponse({ error: error.publicMessage }, error.status);
        }
        LOG.error(`Failed to save agent config: ${errorMessage(error)}`);
        return jsonResponse({ error: "agent_config persistence unavailable" }, 503);
      }
    }

    case "/users": {
      if (request.method !== "GET") {
        return methodNotAllowed(["GET"]);
      }
      return jsonBodyResponse(cachedResponseBodies.users);
    }

    default:
      return jsonResponse({ error: "not found" }, 404);
  }
}

// ── Main ───────────────────────────────────────────────────────────

let server: ReturnType<typeof Bun.serve> | null = null;

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  LOG.info(`Received ${signal}; shutting down`);
  if (pollingTimer) clearTimeout(pollingTimer);

  server?.stop(true);
  if (pollingPromise) await pollingPromise.catch(() => undefined);
  await mongoose.disconnect().catch((error: unknown) => {
    LOG.warn(`MongoDB shutdown failed: ${errorMessage(error)}`);
  });
}

async function main() {
  replaceCachedState(await loadSeedData());

  server = Bun.serve({
    port: PORT,
    hostname: HOST,
    fetch: routeRequest,
  });
  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));
  schedulePoll(0);

  LOG.info(`Stream server listening on http://${HOST}:${PORT}`);
  LOG.info(`MongoDB: ${redactMongoUri(MONGODB_URI)}  Poll: ${POLL_INTERVAL}ms`);
  LOG.info(`Endpoints: GET /health  GET /domains  GET /users  GET/PUT /agent-config`);
  LOG.info(`API auth: ${API_KEY || DIAMOND_KEY ? "configured" : ALLOW_UNAUTHENTICATED ? "disabled by ALLOW_UNAUTHENTICATED" : "required but missing keys"}`);
  LOG.info(`Config write key: ${CONFIG_WRITE_KEY ? "configured" : "using API auth"}`);
  LOG.info(`Seed file: ${SEED_FILE}  (${cachedState.domains.length} domains, ${cachedState.waf_rules.length} rules)`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    LOG.error("Stream server failed to start:", error);
    process.exitCode = 1;
  });
}
