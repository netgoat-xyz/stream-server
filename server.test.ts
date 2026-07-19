import { describe, expect, test } from "bun:test";
import { buildCachedState, normalizeAgentConfig } from "./server";
import { normalizeSeedData } from "./scripts/seed-mongo";

describe("normalizeAgentConfig", () => {
  test("clamps numeric input and rejects unsafe headers", () => {
    const config = normalizeAgentConfig({
      cache: { enabled: true, ttl_seconds: -10, max_entries: "250" },
      rate_limit: { requests_per_minute: 2_000_000, key: "invalid" },
      koda_waf: { threshold: 9, feature_header: "bad header" },
    });

    expect(config.cache.enabled).toBe(true);
    expect(config.cache.ttl_seconds).toBe(1);
    expect(config.cache.max_entries).toBe(250);
    expect(config.rate_limit.requests_per_minute).toBe(1_000_000);
    expect(config.rate_limit.key).toBe("ip");
    expect(config.koda_waf.threshold).toBe(1);
    expect(config.koda_waf.feature_header).toBe("X-KodaWaf-Features");
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
    expect(state.users).toEqual([
      { id: "user-1", username: "Alice", email: "alice@example.com", role: "user" },
    ]);
    expect(state.zero_trust_enabled).toBe(true);
    expect(state.agent_config.metrics).toEqual({ enabled: true, path: "/metrics" });
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
