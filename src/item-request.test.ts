import assert from "node:assert/strict";
import test from "node:test";
import { type Item, ItemCategory, ItemFieldType } from "@1password/sdk";
import {
  FILL_SENTINEL,
  buildCredentialFields,
  buildManagedTags,
  buildProvenanceFields,
  credentialReferences,
  isManagedItem,
  summarizeRequestItem,
} from "./item-request.js";

test("buildManagedTags adds managed/status/project tags and dedupes user tags", () => {
  const tags = buildManagedTags("My Project", { id: "ENG-1" }, ["env:prod", "mcp-managed"]);

  assert(tags.includes("mcp-managed"));
  assert(tags.includes("awaiting-fill"));
  assert(tags.includes("project:my-project"));
  assert(tags.includes("linear:ENG-1"));
  assert(tags.includes("env:prod"));
  assert.equal(tags.filter((tag) => tag === "mcp-managed").length, 1);
});

test("buildManagedTags omits the linear tag when no ticket id is given", () => {
  const tags = buildManagedTags("Solo", undefined, []);

  assert(!tags.some((tag) => tag.startsWith("linear:")));
});

test("buildProvenanceFields records visible text fields with a deterministic timestamp", () => {
  const requestedAt = new Date("2026-06-26T10:00:00.000Z");
  const fields = buildProvenanceFields({
    project: "Billing",
    justification: "Stripe access",
    ticket: { id: "ENG-9", url: "https://linear.app/x/ENG-9" },
    requestedAt,
  });
  const byId = new Map(fields.map((field) => [field.id, field]));

  assert.equal(byId.get("mcp_prov_project")?.value, "Billing");
  assert.equal(byId.get("mcp_prov_justification")?.value, "Stripe access");
  assert.equal(byId.get("mcp_prov_status")?.value, "awaiting-fill");
  assert.equal(byId.get("mcp_prov_requested_at")?.value, requestedAt.toISOString());
  assert.equal(byId.get("mcp_prov_ticket_id")?.value, "ENG-9");
  for (const field of fields) {
    assert.equal(field.fieldType, ItemFieldType.Text);
  }
});

test("buildCredentialFields writes the sentinel for secrets and keeps known values", () => {
  const fields = buildCredentialFields(
    [{ title: "api_key" }, { title: "api_key" }, { title: "note", fieldType: "Text" }],
    [{ title: "username", value: "alice" }],
  );
  const secret = fields.filter((field) => field.fieldType === ItemFieldType.Concealed);

  assert.equal(secret.length, 2);
  for (const field of secret) {
    assert.equal(field.value, FILL_SENTINEL);
  }
  assert.equal(new Set(fields.map((field) => field.id)).size, fields.length);
  const username = fields.find((field) => field.title === "username");
  assert.equal(username?.value, "alice");
  assert.equal(username?.fieldType, ItemFieldType.Text);
});

function managedItem(fields: Item["fields"], tags: string[]): Item {
  return {
    id: "item-1",
    title: "Stripe API Key",
    category: ItemCategory.Login,
    vaultId: "vault-1",
    fields,
    sections: [],
    notes: "",
    tags,
    websites: [],
    version: 1,
    files: [],
    createdAt: new Date("2026-06-26T10:00:00.000Z"),
    updatedAt: new Date("2026-06-26T10:00:00.000Z"),
  };
}

test("summarizeRequestItem reports awaiting-fill while the sentinel remains", () => {
  const item = managedItem(
    [
      ...buildProvenanceFields({
        project: "Billing",
        justification: "Stripe access",
        requestedAt: new Date("2026-06-26T10:00:00.000Z"),
      }),
      ...buildCredentialFields([{ title: "api_key" }]),
    ],
    ["mcp-managed", "awaiting-fill", "project:billing"],
  );

  const summary = summarizeRequestItem(item);
  assert.equal(summary.project, "Billing");
  assert.equal(summary.justification, "Stripe access");
  assert.equal(summary.filled, false);
  assert.equal(summary.pendingFieldCount, 1);
});

test("summarizeRequestItem reports filled once the user replaces the sentinel", () => {
  const fields = [
    ...buildProvenanceFields({
      project: "Billing",
      justification: "Stripe access",
      requestedAt: new Date("2026-06-26T10:00:00.000Z"),
    }),
    ...buildCredentialFields([{ title: "api_key" }]),
  ].map((field) =>
    field.fieldType === ItemFieldType.Concealed ? { ...field, value: "sk_live_real" } : field,
  );

  const summary = summarizeRequestItem(managedItem(fields, ["mcp-managed"]));
  assert.equal(summary.filled, true);
  assert.equal(summary.pendingFieldCount, 0);
});

test("credentialReferences returns op:// paths only for credential-section fields", () => {
  const item = managedItem(
    [
      ...buildProvenanceFields({
        project: "Billing",
        justification: "Stripe access",
        requestedAt: new Date("2026-06-26T10:00:00.000Z"),
      }),
      ...buildCredentialFields([{ title: "api_key" }, { title: "webhook_secret" }]),
    ],
    ["mcp-managed"],
  );

  const references = credentialReferences(item);
  assert.equal(references.length, 2);
  assert(references.every((reference) => reference.startsWith("op://vault-1/item-1/credentials/")));
});

test("isManagedItem recognizes the managed tag", () => {
  assert.equal(isManagedItem(["prod", "mcp-managed"]), true);
  assert.equal(isManagedItem(["prod"]), false);
});
