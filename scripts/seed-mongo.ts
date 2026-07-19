#!/usr/bin/env bun
/**
 * Seeds the control-plane collections from seed-data.json.
 *
 * Existing records are upserted by default. Set SEED_RESET=true to clear the
 * replaceable domain and WAF collections before inserting the seed. User
 * records are always upserted so this utility cannot erase application users.
 * Unrelated application collections are never dropped.
 */
import { MongoClient, type Collection, type Document, type Filter } from "mongodb";

const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017";
const MONGODB_DB = process.env.MONGODB_DB || "netgoat";
const SEED_FILE = process.env.SEED_FILE || "./seed-data.json";
const SEED_RESET = process.env.SEED_RESET === "true";
const MAX_SEED_BYTES = 10 * 1024 * 1024;

type PlainRecord = Record<string, unknown>;

interface SeedData {
  domains: PlainRecord[];
  waf_rules: PlainRecord[];
  users: PlainRecord[];
  zero_trust_enabled: boolean;
  agent_config: PlainRecord;
}

function asRecord(value: unknown): PlainRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as PlainRecord
    : {};
}

function records(value: unknown): PlainRecord[] {
  return Array.isArray(value) ? value.map(asRecord).filter((item) => Object.keys(item).length > 0) : [];
}

function cleanDocument(value: PlainRecord): PlainRecord {
  const document = { ...value };
  delete document._id;
  return document;
}

export function normalizeSeedData(value: unknown): SeedData {
  const source = asRecord(value);
  const domains = records(source.domains).map((raw) => {
    const domain = cleanDocument(raw);
    domain.active = raw.active !== false;
    domain.subdomains = records(raw.subdomains).map((subdomain) => ({
      ...cleanDocument(subdomain),
      active: subdomain.active !== false,
      waf_rules: records(subdomain.waf_rules).map((rule) => ({
        ...cleanDocument(rule),
        enabled: rule.enabled !== false,
      })),
    }));
    domain.waf_rules = records(raw.waf_rules).map((rule) => ({
      ...cleanDocument(rule),
      enabled: rule.enabled !== false,
    }));
    return domain;
  });

  const wafRules = records(source.waf_rules).map((rule) => ({
    ...cleanDocument(rule),
    enabled: rule.enabled !== false,
  }));

  const users = records(source.users).map((raw) => {
    const user = cleanDocument(raw);
    user.name = String(raw.name || raw.username || "").trim();
    delete user.username;
    return user;
  });

  return {
    domains,
    waf_rules: wafRules,
    users,
    zero_trust_enabled: source.zero_trust_enabled === true,
    agent_config: asRecord(source.agent_config),
  };
}

function identityFilter(document: PlainRecord, fallbackField: string): Filter<Document> {
  if (typeof document.id === "string" && document.id.trim()) {
    return { id: document.id };
  }
  const fallback = document[fallbackField];
  if (typeof fallback !== "string" || !fallback.trim()) {
    throw new Error(`seed record is missing id and ${fallbackField}`);
  }
  return { [fallbackField]: fallback };
}

async function upsertDocuments(
  collection: Collection,
  documents: PlainRecord[],
  fallbackField: string,
): Promise<void> {
  if (documents.length === 0) return;
  await collection.bulkWrite(
    documents.map((document) => ({
      updateOne: {
        filter: identityFilter(document, fallbackField),
        update: { $set: document },
        upsert: true,
      },
    })),
    { ordered: true },
  );
}

function redactMongoUri(uri: string): string {
  try {
    const parsed = new URL(uri);
    if (parsed.username) parsed.username = "***";
    if (parsed.password) parsed.password = "***";
    return parsed.toString();
  } catch {
    return uri.replace(/\/\/[^/@]*@/, "//***@");
  }
}

async function readSeedData(): Promise<SeedData> {
  const file = Bun.file(SEED_FILE);
  if (!await file.exists()) throw new Error(`seed file not found: ${SEED_FILE}`);
  if (file.size > MAX_SEED_BYTES) throw new Error(`seed file exceeds ${MAX_SEED_BYTES} bytes`);
  return normalizeSeedData(JSON.parse(await file.text()));
}

export async function main(): Promise<void> {
  console.log(`Connecting to ${redactMongoUri(MONGODB_URI)}...`);
  const client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });

  try {
    const data = await readSeedData();
    await client.connect();
    const db = client.db(MONGODB_DB);

    const domains = db.collection("domains");
    const wafRules = db.collection("waf_rules");
    // Better Auth and the frontend explicitly use the singular `user` collection.
    const users = db.collection("user");

    if (SEED_RESET) {
      await Promise.all([
        domains.deleteMany({}),
        wafRules.deleteMany({}),
      ]);
      console.log("Cleared domains and waf_rules seed collections");
    }

    await Promise.all([
      upsertDocuments(domains, data.domains, "domain"),
      upsertDocuments(wafRules, data.waf_rules, "name"),
      upsertDocuments(users, data.users, "name"),
      db.collection("settings").findOneAndUpdate(
        {},
        {
          $set: {
            zeroTrustEnabled: data.zero_trust_enabled,
            agentConfig: data.agent_config,
          },
        },
        { upsert: true },
      ),
    ]);

    console.log(
      `Seeded ${data.domains.length} domains, ${data.waf_rules.length} WAF rules, and ${data.users.length} users`,
    );
  } finally {
    await client.close();
  }
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : "MongoDB seeding failed");
    process.exitCode = 1;
  });
}
