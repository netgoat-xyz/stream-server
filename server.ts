#!/usr/bin/env bun
import { timingSafeEqual } from "node:crypto";
import mongoose from "mongoose";
import DomainModel from "./models/Domain";
import SettingsModel from "./models/Settings";
import UserModel from "./models/User";

interface Subdomain {
  id: string;
  subdomain: string;
  full_domain: string;
  target_url: string;
  active: boolean;
}

interface Domain {
  id: string;
  domain: string;
  target_url: string;
  certificate_pem?: string;
  private_key_pem?: string;
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

interface CachedState {
  domains: Domain[];
  waf_rules: WafRule[];
  users: User[];
  zero_trust_enabled: boolean;
  agent_config: AgentConfig;
  last_pulled: Date;
}

const PORT = parseInt(process.env.PORT || "8787");
const HOST = process.env.HOST || "0.0.0.0";
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017";
const MONGODB_DB = process.env.MONGODB_DB || "netgoat";
const API_KEY = process.env.API_KEY || "";
const DIAMOND_KEY = process.env.DIAMOND_KEY || "";
const ALLOW_UNAUTHENTICATED = process.env.ALLOW_UNAUTHENTICATED === "true";
const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL || "5000");
const SEED_FILE = process.env.SEED_FILE || "./seed-data.json";
const LOG_LEVEL = process.env.LOG_LEVEL || "info";
const MAX_CONFIG_BODY_BYTES = 64 * 1024;

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
  const n = typeof value === "number" ? value : parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

function clampFloat(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === "number" ? value : parseFloat(String(value ?? ""));
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
  if (!trimmed || trimmed.length > maxLength || trimmed.includes("\0")) return fallback;
  return trimmed;
}

function safeHeader(value: unknown, fallback: string): string {
  const header = safePath(value, fallback, 128);
  return /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(header) ? header : fallback;
}

function normalizeAgentConfig(input: unknown): AgentConfig {
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
      path: safePath(raw.metrics?.path, base.metrics.path),
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

let connected = false;

async function connectMongo(uri: string): Promise<boolean> {
  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000,
      dbName: MONGODB_DB,
    });
    await mongoose.connection.db!.command({ ping: 1 });
    LOG.info(`Connected to MongoDB at ${uri.replace(/\/\/.*@/, "//***@")}`);
    connected = true;
    return true;
  } catch (err) {
    LOG.warn(`MongoDB unavailable at ${uri}:`, err);
    connected = false;
    return false;
  }
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

async function loadSeedData(): Promise<CachedState> {
  try {
    const file = Bun.file(SEED_FILE);
    const exists = await file.exists();
    if (!exists) {
      LOG.warn(`Seed file ${SEED_FILE} not found, using empty state`);
      return emptyState();
    }
    const text = await file.text();
    const parsed = JSON.parse(text);
    LOG.info(`Loaded seed data from ${SEED_FILE}`);
    return {
      domains: parsed.domains || [],
      waf_rules: parsed.waf_rules || [],
      users: parsed.users || [],
      zero_trust_enabled: parsed.zero_trust_enabled ?? false,
      agent_config: normalizeAgentConfig(parsed.agent_config),
      last_pulled: new Date(),
    };
  } catch (err) {
    LOG.warn(`Failed to load seed file ${SEED_FILE}:`, err);
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

async function pullFromMongo(): Promise<CachedState | null> {
  try {
    // ── Domains ──────────────────────────────────────────────────
    const domainDocs = await DomainModel.find({}).lean();
    const domains: Domain[] = domainDocs.map((doc: any) => ({
      id: String(doc._id),
      domain: doc.domain || "",
      target_url: doc.target_url || "",
      certificate_pem: doc.certificate_pem || "",
      private_key_pem: doc.private_key_pem || "",
      team_id: doc.team_id ? String(doc.team_id) : "",
      active: doc.active === true,
      subdomains: (doc.subdomains || []).map((s: any) => ({
        id: String(s._id || s.subdomain),
        subdomain: s.subdomain || "",
        full_domain: s.full_domain || "",
        target_url: s.target_url || "",
        active: s.active === true,
      })),
    }));

    // ── WAF Rules — flatten from all domains ─────────────────────
    const waf_rules: WafRule[] = [];
    for (const doc of domainDocs) {
      for (const rule of (doc as any).waf_rules || []) {
        waf_rules.push({
          id: String(rule._id || rule.name),
          name: rule.name || "",
          expression: rule.expression || "",
          action: rule.action || "BLOCK",
          priority: rule.priority ?? 0,
          proxy_config_id: "",
        });
      }
    }

    // ── Users ────────────────────────────────────────────────────
    const userDocs = await UserModel.find({}).lean();
    const users: User[] = userDocs.map((doc: any) => ({
      id: String(doc._id),
      username: doc.name || doc.email?.split("@")[0] || "",
      email: doc.email || "",
      role: doc.role || "user",
    }));

    let zero_trust_enabled = false;
    const settingsDoc = await SettingsModel.findOne({}).select("agentConfig zeroTrustEnabled").lean();
    const agent_config = normalizeAgentConfig((settingsDoc as any)?.agentConfig);
    zero_trust_enabled = (settingsDoc as any)?.zeroTrustEnabled === true;

    LOG.info(
      `Pulled from MongoDB: ${domains.length} domains, ${waf_rules.length} rules, ${users.length} users`
    );

    return {
      domains,
      waf_rules,
      users,
      zero_trust_enabled,
      agent_config,
      last_pulled: new Date(),
    };
  } catch (err) {
    LOG.error("MongoDB pull failed:", err);
    return null;
  }
}

// ── State updater ──────────────────────────────────────────────────

let pollingTimer: ReturnType<typeof setInterval> | null = null;

async function updateState(mongoConnected: boolean) {
  LOG.debug("Polling for config updates...");

  if (mongoConnected) {
    const result = await pullFromMongo();
    if (result) {
      cachedState = result;
      return;
    }
  }

  if (cachedState.domains.length === 0 && cachedState.last_pulled.getTime() === 0) {
    cachedState = await loadSeedData();
  }
}

// ── Auth middleware ────────────────────────────────────────────────

function checkAuth(request: Request): boolean {
  if (!API_KEY && !DIAMOND_KEY) return ALLOW_UNAUTHENTICATED;

  const requestKeys = [
    request.headers.get("X-API-Key") || "",
    (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, ""),
    request.headers.get("X-Diamond-Key") || "",
    request.headers.get("X-Zero-Trust-Key") || "",
  ].filter(Boolean);

  const configuredKeys = [API_KEY, DIAMOND_KEY].filter(Boolean);
  return requestKeys.some(rk => configuredKeys.some(ck => safeEqual(rk, ck)));
}

function safeEqual(a: string, b: string): boolean {
  if (!a || !b) return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function unauthorized(): Response {
  return new Response(JSON.stringify({ error: "unauthorized" }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  });
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function readJSONBody(request: Request): Promise<any> {
  const contentLength = Number(request.headers.get("content-length") || "0");
  if (contentLength > MAX_CONFIG_BODY_BYTES) {
    throw new Error("request body too large");
  }
  const text = await request.text();
  if (new Blob([text]).size > MAX_CONFIG_BODY_BYTES) {
    throw new Error("request body too large");
  }
  return JSON.parse(text || "{}");
}

async function saveAgentConfig(agentConfig: AgentConfig): Promise<void> {
  cachedState = {
    ...cachedState,
    agent_config: agentConfig,
    last_pulled: new Date(),
  };
  if (!connected) return;
  await SettingsModel.findOneAndUpdate(
    {},
    { $set: { agentConfig } },
    { new: true, upsert: true, setDefaultsOnInsert: true }
  );
}

async function routeRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (!checkAuth(request)) return unauthorized();

  switch (path) {
    case "/health":
    case "": {
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
        auth_required: !ALLOW_UNAUTHENTICATED,
        last_pulled: cachedState.last_pulled.toISOString(),
      });
    }

    case "/domains": {
      if (request.method !== "GET") {
        return jsonResponse({ error: "method not allowed" }, 405);
      }
      const payload: DomainsResponse = {
        domains: cachedState.domains,
        waf_rules: cachedState.waf_rules,
        zero_trust_enabled: cachedState.zero_trust_enabled,
        agent_config: cachedState.agent_config,
      };
      return jsonResponse(payload);
    }

    case "/agent-config": {
      if (request.method === "GET") {
        return jsonResponse({ agent_config: cachedState.agent_config });
      }
      if (request.method !== "PUT") {
        return jsonResponse({ error: "method not allowed" }, 405);
      }
      try {
        const body = await readJSONBody(request);
        const agentConfig = normalizeAgentConfig(body.agent_config ?? body);
        await saveAgentConfig(agentConfig);
        return jsonResponse({ agent_config: cachedState.agent_config });
      } catch (err) {
        LOG.warn("Rejected agent config update:", err);
        return jsonResponse({ error: "invalid agent_config" }, 400);
      }
    }

    case "/users": {
      if (request.method !== "GET") {
        return jsonResponse({ error: "method not allowed" }, 405);
      }
      return jsonResponse({ users: cachedState.users });
    }

    default:
      return jsonResponse({ error: "not found" }, 404);
  }
}

// ── Main ───────────────────────────────────────────────────────────

async function main() {
  connectMongo(MONGODB_URI);

  cachedState = await loadSeedData();

  setTimeout(() => updateState(connected), 500);

  pollingTimer = setInterval(() => {
    updateState(connected);
  }, POLL_INTERVAL);

  Bun.serve({
    port: PORT,
    hostname: HOST,
    fetch: routeRequest,
  });

  LOG.info(`Stream server listening on http://${HOST}:${PORT}`);
  LOG.info(`MongoDB: ${MONGODB_URI.replace(/\/\/.*@/, "//***@")}  Poll: ${POLL_INTERVAL}ms`);
  LOG.info(`Endpoints: GET /health  GET /domains  GET /users  GET/PUT /agent-config`);
  LOG.info(`API auth: ${API_KEY || DIAMOND_KEY ? "configured" : ALLOW_UNAUTHENTICATED ? "disabled by ALLOW_UNAUTHENTICATED" : "required but missing keys"}`);
  LOG.info(`Seed file: ${SEED_FILE}  (${cachedState.domains.length} domains, ${cachedState.waf_rules.length} rules)`);
}

main();
