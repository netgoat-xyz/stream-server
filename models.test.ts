import { describe, expect, test } from "bun:test";
import Analytics from "./models/Analytics";
import DNSRecord from "./models/DNSRecord";
import Domain from "./models/Domain";
import Incident from "./models/Incident";
import Invoice from "./models/Invoice";
import Post from "./models/Post";
import ProxyConfig from "./models/ProxyConfig";
import Session from "./models/Session";
import Team, { activeInviteQuery } from "./models/Team";

describe("schema correctness", () => {
  test("validates complete IP addresses", () => {
    expect(DNSRecord.validateRecord("A", "192.168.1.10")).toBe(true);
    expect(DNSRecord.validateRecord("A", "999.168.1.10")).toBe(false);
    expect(DNSRecord.validateRecord("AAAA", "2001:db8::1")).toBe(true);
    expect(DNSRecord.validateRecord("AAAA", "2001:::1")).toBe(false);
  });

  test("matches invite state on the same embedded record", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    expect(activeInviteQuery("invite-token", now)).toEqual({
      invites: {
        $elemMatch: {
          token: "invite-token",
          accepted: false,
          expires_at: { $gt: now },
        },
      },
    });
  });

  test("declares no duplicate indexes", () => {
    const models = [Analytics, DNSRecord, Domain, Incident, Invoice, Post, ProxyConfig, Session, Team];
    for (const model of models) {
      const signatures = model.schema.indexes().map(([fields]) => JSON.stringify(fields));
      expect(new Set(signatures).size, model.modelName).toBe(signatures.length);
    }
  });

  test("expires sessions and maintains mutable document timestamps", () => {
    const sessionExpiry = Session.schema.indexes().find(([fields]) => fields.expiresAt === 1);
    expect(sessionExpiry?.[1].expireAfterSeconds).toBe(0);
    expect(Incident.schema.get("timestamps")).toEqual({ createdAt: "createdAt", updatedAt: "updatedAt" });
    expect(Post.schema.get("timestamps")).toEqual({ createdAt: "createdAt", updatedAt: "updatedAt" });
    expect(Invoice.schema.get("timestamps")).toEqual({ createdAt: "created_at", updatedAt: "updated_at" });
    expect(Team.schema.get("timestamps")).toEqual({ createdAt: "created_at", updatedAt: "updated_at" });
    expect(Domain.schema.path("route_policy")).toBeDefined();
    expect(Domain.schema.path("subdomains.route_policy")).toBeDefined();
  });
});
