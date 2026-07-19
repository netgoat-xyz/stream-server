#!/usr/bin/env bun
/**
 * Seeds MongoDB with the data from seed-data.json.
 *
 * Usage:
 *   bun run scripts/seed-mongo.ts
 *
 * Environment:
 *   MONGODB_URI  (default: mongodb://localhost:27017)
 *   MONGODB_DB   (default: netgoat)
 *   SEED_FILE    (default: ./seed-data.json)
 */
import { MongoClient } from "mongodb";

const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017";
const MONGODB_DB = process.env.MONGODB_DB || "netgoat";
const SEED_FILE = process.env.SEED_FILE || "./seed-data.json";

async function main() {
  console.log(`Connecting to ${MONGODB_URI.replace(/\/\/.*@/, "//***@")}...`);
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(MONGODB_DB);

  const file = Bun.file(SEED_FILE);
  const data = JSON.parse(await file.text());

  // Clear existing data
  const collections = await db.listCollections().toArray();
  for (const c of collections) {
    await db.collection(c.name).drop();
    console.log(`Dropped collection: ${c.name}`);
  }

  // Seed domains
  if (data.domains?.length) {
    const domains = data.domains.map((d: Record<string, unknown>) => {
      const { subdomains, ...domain } = d;
      return domain;
    });
    await db.collection("domains").insertMany(domains);
    console.log(`Seeded ${domains.length} domains`);

    // Seed subdomains separately
    const subdomains = data.domains.flatMap(
      (d: Record<string, unknown>) => (d.subdomains as Array<Record<string, unknown>> || []).map(
        (s: Record<string, unknown>) => ({ ...s, domain_id: d.id })
      )
    );
    if (subdomains.length) {
      await db.collection("subdomains").insertMany(subdomains);
      console.log(`Seeded ${subdomains.length} subdomains`);
    }
  }

  // Seed WAF rules
  if (data.waf_rules?.length) {
    await db.collection("waf_rules").insertMany(data.waf_rules);
    console.log(`Seeded ${data.waf_rules.length} WAF rules`);
  }

  // Seed users
  if (data.users?.length) {
    await db.collection("users").insertMany(data.users);
    console.log(`Seeded ${data.users.length} users`);
  }

  // Seed settings
  await db.collection("settings").updateOne(
    { key: "zero_trust_enabled" },
    { $set: { value: data.zero_trust_enabled ?? false } },
    { upsert: true }
  );
  console.log(`Set zero_trust_enabled = ${data.zero_trust_enabled}`);

  await client.close();
  console.log("Done.");
}

main().catch(console.error);
