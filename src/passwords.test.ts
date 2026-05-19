import assert from "node:assert/strict";
import test from "node:test";
import { ItemCategory, ItemFieldType, type Item } from "@1password/sdk";
import { upsertPasswordField } from "./passwords.js";

test("upsertPasswordField does not mutate existing item fields", () => {
  const item: Item = {
    id: "item-1",
    title: "Login",
    category: ItemCategory.Login,
    vaultId: "vault-1",
    fields: [
      {
        id: "password",
        title: "password",
        fieldType: ItemFieldType.Text,
        value: "old-secret",
      },
    ],
    sections: [],
    notes: "",
    tags: [],
    websites: [],
    version: 1,
    files: [],
    createdAt: new Date("2026-05-01T00:00:00.000Z"),
    updatedAt: new Date("2026-05-01T00:00:00.000Z"),
  };
  const originalField = item.fields[0]!;

  const updated = upsertPasswordField(item, "new-secret");

  assert.equal(originalField.value, "old-secret");
  assert.equal(originalField.fieldType, ItemFieldType.Text);
  assert.equal(updated.fields[0]?.value, "new-secret");
  assert.equal(updated.fields[0]?.fieldType, ItemFieldType.Concealed);
  assert.notEqual(updated.fields[0], originalField);
});
