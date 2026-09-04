import { describe, expect, test } from "bun:test";
import {
  buildCachedState,
  normalizeAgentConfig,
  normalizeRoutePolicy,
  readJSONBody,
  redactMongoUri,
} from "./server";
import { normalizeSeedData } from "./scripts/seed-mongo";

describe("normalizeAgentConfig", () => {
  test("clamps numeric input and rejects unsafe headers", () => {
    const config = normalizeAgentConfig({
      cache: { enabled: true, ttl_seconds: -10, max_entries: "250" },
      rate_limit: { requests_per_minute: 2_000_000, key: "invalid" },
      metrics: { enabled: true, path: "https://example.com/metrics" },
      koda_waf: { threshold: 9, feature_header: "bad header" },
    });

    expect(config.cache.enabled).toBe(true);
    expect(config.cache.ttl_seconds).toBe(1);
    expect(config.cache.max_entries).toBe(250);
    expect(config.rate_limit.requests_per_minute).toBe(1_000_000);
    expect(config.rate_limit.key).toBe("ip");
    expect(config.metrics.path).toBe("/__netgoat/metrics");
    expect(config.koda_waf.threshold).toBe(1);
    expect(config.koda_waf.feature_header).toBe("X-KodaWaf-Features");
  });

  test("does not partially parse malformed numbers", () => {
    const config = normalizeAgentConfig({ cache: { max_entries: "250garbage" } });
    expect(config.cache.max_entries).toBe(1024);
  });
});

describe("request parsing and secret redaction", () => {
  test("parses a bounded JSON request", async () => {
    const request = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ metrics: { enabled: true } }),
    });
    expect(await readJSONBody(request)).toEqual({ metrics: { enabled: true } });
  });

  test("rejects declared and streamed oversized bodies", async () => {
    const declared = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Length": "65537", "Content-Type": "application/json" },
      body: "{}",
    });
    await expect(readJSONBody(declared)).rejects.toThrow("request body too large");

    const streamed = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: `"${"x".repeat(65537)}"`,
    });
    await expect(readJSONBody(streamed)).rejects.toThrow("request body too large");
  });

  test("rejects unsupported media types and malformed JSON", async () => {
    const wrongType = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Type": "text/plain" },
      body: "{}",
    });
    await expect(readJSONBody(wrongType)).rejects.toThrow("content-type must be application/json");

    const malformed = new Request("http://localhost/agent-config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: "{",
    });
    await expect(readJSONBody(malformed)).rejects.toThrow("invalid JSON body");
  });

  test("redacts MongoDB credentials", () => {
    const redacted = redactMongoUri("mongodb+srv://alice:secret@cluster.example/netgoat");
    expect(redacted).not.toContain("alice");
    expect(redacted).not.toContain("secret");
    expect(redacted).toContain("cluster.example");
  });
});

describe("buildCachedState", () => {
  test("publishes only active routes, users, rules, and healthy upstreams", () => {
    const state = buildCachedState({
      domainDocs: [
        {
          _id: "domain-1",
          domain: "Example.COM",
          target_url: "https://primary.internal",
          active: true,
          subdomains: [
            {
              _id: "sub-1",
              subdomain: "API",
              full_domain: "api.example.com",
              target_url: "https://api-primary.internal",
              active: true,
            },
            { subdomain: "old", full_domain: "old.example.com", active: false },
          ],
          waf_rules: [
            { _id: "rule-1", name: "block bots", expression: "bot", priority: 10 },
            { name: "disabled", expression: "never", enabled: false },
          ],
        },
        { _id: "domain-2", domain: "disabled.example", active: false },
      ],
      proxyConfigDocs: [
        {
          domain_id: "domain-1",
          upstream_servers: [
            { url: "https://primary.internal" },
            { url: "https://secondary.internal" },
            { url: "https://down.internal", down: true },
          ],
        },
        {
          domain_id: "domain-1",
          subdomain: "api",
          upstream_servers: [{ url: "https://api-secondary.internal" }],
        },
      ],
      globalRuleDocs: [
        { _id: "global-1", name: "global", expression: "attack", action: "allow", priority: 20 },
      ],
      userDocs: [
        { _id: "user-1", name: "Alice", email: "ALICE@example.com" },
        { _id: "user-2", name: "Banned", banned: true },
      ],
      settingsDoc: {
        zeroTrustEnabled: true,
        agentConfig: { metrics: { enabled: true, path: "/metrics" } },
      },
    });

    expect(state.domains).toHaveLength(1);
    expect(state.domains[0]?.domain).toBe("example.com");
    expect(state.domains[0]?.target_urls).toEqual(["https://secondary.internal"]);
    expect(state.domains[0]?.subdomains).toHaveLength(1);
    expect(state.domains[0]?.subdomains[0]?.target_urls).toEqual(["https://api-secondary.internal"]);
    expect(state.waf_rules.map((rule) => rule.name)).toEqual(["global", "block bots"]);
    expect(state.waf_rules[0]?.action).toBe("ALLOW");
    expect(state.waf_rules.find((rule) => rule.name === "block bots")?.hosts).toEqual([
      "example.com",
      "api.example.com",
    ]);
    expect(state.waf_rules.find((rule) => rule.name === "global")?.expression).toBe("attack");
    expect(JSON.parse(JSON.stringify(state.domains[0]))).not.toHaveProperty("policy");
    expect(state.users).toEqual([
      { id: "user-1", username: "Alice", email: "alice@example.com", role: "user" },
    ]);
    expect(state.zero_trust_enabled).toBe(true);
    expect(state.agent_config.metrics).toEqual({ enabled: true, path: "/metrics" });
  });

  test("scopes proxy WAF rules to their resolved route host", () => {
    const state = buildCachedState({
      domainDocs: [{ _id: "domain-1", domain: "example.com", subdomains: [{ subdomain: "api" }] }],
      proxyConfigDocs: [{ _id: "proxy-1", domain_id: "domain-1", subdomain: "api" }],
      globalRuleDocs: [
        { _id: "scoped", name: "api only", expression: "Path == '/private'", proxy_config_id: "proxy-1" },
        { _id: "stale", name: "stale scope", expression: "true", proxy_config_id: "missing" },
      ],
      userDocs: [],
      settingsDoc: {},
    });
    expect(state.waf_rules).toHaveLength(1);
    expect(state.waf_rules[0]?.hosts).toEqual(["api.example.com"]);
  });

  test("reads the legacy zero-trust settings record", () => {
    const state = buildCachedState({
      domainDocs: [],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [],
      settingsDoc: {},
      legacyZeroTrustDoc: { value: "true" },
    });

    expect(state.zero_trust_enabled).toBe(true);
  });

  test("emits Mongo route_policy as agent-facing policy and keeps certs plus WAF", () => {
    const state = buildCachedState({
      domainDocs: [{
        _id: "domain-1",
        domain: "example.com",
        target_url: "https://origin.internal",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----",
        private_key_pem: "-----BEGIN PRIVATE KEY-----\nROOT\n-----END PRIVATE KEY-----",
        route_policy: {
          cache: { enabled: true, ttl_seconds: 30, unknown_flag: true },
          bandwidth: { enabled: true, bytes_per_second: 4096, burst_bytes: 8192, key: "host" },
          rate_limit: { enabled: true },
        },
        subdomains: [{
          _id: "sub-1",
          subdomain: "api",
          full_domain: "api.example.com",
          target_url: "https://api.internal",
          certificate_pem: "-----BEGIN CERTIFICATE-----\nAPI\n-----END CERTIFICATE-----",
          private_key_pem: "-----BEGIN PRIVATE KEY-----\nAPI\n-----END PRIVATE KEY-----",
          route_policy: { cache: { ttl_seconds: 15 } },
        }],
        waf_rules: [{ _id: "rule-1", name: "block bots", expression: "bot", priority: 10 }],
      }],
      proxyConfigDocs: [],
      globalRuleDocs: [
        { _id: "global-1", name: "global", expression: "attack", action: "allow", priority: 20 },
      ],
      userDocs: [],
      settingsDoc: {},
    });

    const domainJson = JSON.parse(JSON.stringify(state.domains[0]));
    expect(domainJson).not.toHaveProperty("route_policy");
    expect(domainJson.policy).toEqual({
      cache: { enabled: true, ttl_seconds: 30 },
      bandwidth: { enabled: true, bytes_per_second: 4096, burst_bytes: 8192, key: "host" },
    });
    expect(domainJson.certificate_pem).toContain("BEGIN CERTIFICATE");
    expect(domainJson.private_key_pem).toContain("BEGIN PRIVATE KEY");
    expect(domainJson.subdomains[0].policy).toEqual({ cache: { ttl_seconds: 15 } });
    expect(domainJson.subdomains[0].certificate_pem).toContain("API");
    expect(domainJson.subdomains[0].private_key_pem).toContain("API");
    expect(state.waf_rules.map((rule) => rule.name)).toEqual(["global", "block bots"]);
    expect(state.waf_rules.find((rule) => rule.name === "block bots")?.hosts).toEqual([
      "example.com",
      "api.example.com",
    ]);
  });

  test("omits empty policy and drops invalid bandwidth keys", () => {
    const state = buildCachedState({
      domainDocs: [
        {
          _id: "empty",
          domain: "empty.example",
          route_policy: { cache: {}, bandwidth: { key: "asn" } },
        },
        {
          _id: "partial",
          domain: "partial.example",
          route_policy: { bandwidth: { bytes_per_second: 4096, key: "asn" } },
        },
        {
          _id: "seed",
          domain: "seed.example",
          policy: { cache: { enabled: false } },
        },
      ],
      proxyConfigDocs: [],
      globalRuleDocs: [],
      userDocs: [],
      settingsDoc: {},
    });

    const [emptyDomain, partialDomain, seedDomain] = state.domains.map((domain) => JSON.parse(JSON.stringify(domain)));
    expect(emptyDomain).not.toHaveProperty("policy");
    expect(partialDomain.policy).toEqual({ bandwidth: { bytes_per_second: 4096 } });
    expect(seedDomain.policy).toEqual({ cache: { enabled: false } });
  });
});

describe("normalizeRoutePolicy", () => {
  test("drops unknown keys and out-of-range numbers without clamping", () => {
    expect(normalizeRoutePolicy({
      cache: { enabled: true, ttl_seconds: 0, max_entries: 250 },
      bandwidth: { key: "route", bytes_per_second: 512 },
      extra: true,
    })).toEqual({
      cache: { enabled: true, max_entries: 250 },
      bandwidth: { key: "route" },
    });
    expect(normalizeRoutePolicy(null)).toBeUndefined();
    expect(normalizeRoutePolicy({ cache: { ttl_seconds: "30" } })).toEqual({ cache: { ttl_seconds: 30 } });
  });
});

describe("normalizeSeedData", () => {
  test("keeps embedded route data and maps users to the frontend collection schema", () => {
    const seed = normalizeSeedData({
      domains: [{ domain: "example.com", subdomains: [{ subdomain: "api" }] }],
      waf_rules: [{ name: "global", expression: "attack" }],
      users: [{ username: "alice", email: "alice@example.com" }],
      zero_trust_enabled: true,
    });

    expect(seed.domains[0]?.active).toBe(true);
    expect((seed.domains[0]?.subdomains as Array<Record<string, unknown>>)[0]?.active).toBe(true);
    expect(seed.waf_rules[0]?.enabled).toBe(true);
    expect(seed.users[0]?.name).toBe("alice");
    expect(seed.users[0]?.username).toBeUndefined();
    expect(seed.zero_trust_enabled).toBe(true);
  });
});
