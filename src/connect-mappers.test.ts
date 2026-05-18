import assert from "node:assert/strict";
import test from "node:test";
import {
  AutofillBehavior,
  ItemCategory,
  ItemFieldType,
  ItemState,
  VaultType,
  type Item,
  type ItemCreateParams,
} from "@1password/sdk";
import {
  mapConnectFullItemToItem,
  mapConnectItemToItemOverview,
  mapConnectVaultToVault,
  mapConnectVaultToVaultOverview,
  mapSdkItemCreateParamsToConnectItem,
  mapSdkItemToConnectItem,
} from "./connect-mappers.js";

test("maps Connect vault metadata to SDK-shaped vaults", () => {
  const connectVault = {
    id: "vault-1",
    name: "Engineering",
    description: "Team secrets",
    type: "USER_CREATED",
    items: 12,
    contentVersion: 7,
    attributeVersion: 3,
    createdAt: new Date("2026-05-01T10:00:00.000Z"),
    updatedAt: new Date("2026-05-02T10:00:00.000Z"),
  };

  assert.deepEqual(mapConnectVaultToVaultOverview(connectVault), {
    id: "vault-1",
    title: "Engineering",
    description: "Team secrets",
    vaultType: VaultType.UserCreated,
    activeItemCount: 12,
    contentVersion: 7,
    attributeVersion: 3,
    createdAt: new Date("2026-05-01T10:00:00.000Z"),
    updatedAt: new Date("2026-05-02T10:00:00.000Z"),
  });
  assert.deepEqual(mapConnectVaultToVault(connectVault), {
    id: "vault-1",
    title: "Engineering",
    description: "Team secrets",
    vaultType: VaultType.UserCreated,
    activeItemCount: 12,
    contentVersion: 7,
    attributeVersion: 3,
    access: [],
  });
});

test("maps Connect item overviews and full items to SDK-shaped items", () => {
  const connectItem = {
    id: "item-1",
    title: "Database",
    category: "LOGIN",
    vault: { id: "vault-1" },
    tags: ["prod"],
    urls: [{ href: "https://db.example.test", label: "login", primary: true }],
    version: 4,
    createdAt: new Date("2026-05-01T10:00:00.000Z"),
    updatedAt: new Date("2026-05-02T10:00:00.000Z"),
  };
  const fullItem = {
    ...connectItem,
    sections: [{ id: "section-1", label: "Credentials" }],
    fields: [
      { id: "username", purpose: "USERNAME", value: "alice" },
      { id: "password", purpose: "PASSWORD", value: "secret" },
      {
        id: "token",
        section: { id: "section-1" },
        type: "CONCEALED",
        label: "api-token",
        value: "token-secret",
      },
      { id: "notesPlain", purpose: "NOTES", value: "internal note" },
      { id: "otp", type: "OTP", label: "one-time password", otp: "123456" },
    ],
  };

  assert.deepEqual(mapConnectItemToItemOverview(connectItem, "vault-1"), {
    id: "item-1",
    title: "Database",
    category: ItemCategory.Login,
    vaultId: "vault-1",
    websites: [
      {
        url: "https://db.example.test",
        label: "login",
        autofillBehavior: AutofillBehavior.ExactDomain,
      },
    ],
    tags: ["prod"],
    createdAt: new Date("2026-05-01T10:00:00.000Z"),
    updatedAt: new Date("2026-05-02T10:00:00.000Z"),
    state: ItemState.Active,
  });

  assert.deepEqual(mapConnectFullItemToItem(fullItem, "vault-1"), {
    id: "item-1",
    title: "Database",
    category: ItemCategory.Login,
    vaultId: "vault-1",
    fields: [
      {
        id: "username",
        title: "username",
        fieldType: ItemFieldType.Text,
        value: "alice",
      },
      {
        id: "password",
        title: "password",
        fieldType: ItemFieldType.Concealed,
        value: "secret",
      },
      {
        id: "token",
        title: "api-token",
        sectionId: "section-1",
        fieldType: ItemFieldType.Concealed,
        value: "token-secret",
      },
      {
        id: "otp",
        title: "one-time password",
        fieldType: ItemFieldType.Totp,
        value: "123456",
        details: { type: "Otp", content: { code: "123456" } },
      },
    ],
    sections: [{ id: "section-1", title: "Credentials" }],
    notes: "internal note",
    tags: ["prod"],
    websites: [
      {
        url: "https://db.example.test",
        label: "login",
        autofillBehavior: AutofillBehavior.ExactDomain,
      },
    ],
    version: 4,
    files: [],
    createdAt: new Date("2026-05-01T10:00:00.000Z"),
    updatedAt: new Date("2026-05-02T10:00:00.000Z"),
  });
});

test("maps SDK item create and update payloads to Connect FullItem payloads", () => {
  const createParams: ItemCreateParams = {
    vaultId: "vault-1",
    category: ItemCategory.Login,
    title: "Database",
    notes: "internal note",
    tags: ["prod"],
    sections: [{ id: "section-1", title: "Credentials" }],
    websites: [
      {
        url: "https://db.example.test",
        label: "login",
        autofillBehavior: AutofillBehavior.ExactDomain,
      },
    ],
    fields: [
      {
        id: "username",
        title: "username",
        fieldType: ItemFieldType.Text,
        value: "alice",
      },
      {
        id: "password",
        title: "password",
        fieldType: ItemFieldType.Concealed,
        value: "secret",
      },
      {
        id: "token",
        title: "api-token",
        sectionId: "section-1",
        fieldType: ItemFieldType.Concealed,
        value: "token-secret",
      },
    ],
  };

  assert.deepEqual(mapSdkItemCreateParamsToConnectItem(createParams), {
    title: "Database",
    vault: { id: "vault-1" },
    category: "LOGIN",
    tags: ["prod"],
    sections: [{ id: "section-1", label: "Credentials" }],
    urls: [{ href: "https://db.example.test", label: "login", primary: true }],
    fields: [
      { id: "username", purpose: "USERNAME", value: "alice" },
      { id: "password", purpose: "PASSWORD", value: "secret" },
      {
        id: "token",
        label: "api-token",
        section: { id: "section-1" },
        type: "CONCEALED",
        value: "token-secret",
      },
      { id: "notesPlain", purpose: "NOTES", value: "internal note" },
    ],
  });

  const item: Item = {
    ...mapConnectFullItemToItem(
      {
        id: "item-1",
        title: "Database",
        category: "LOGIN",
        vault: { id: "vault-1" },
        tags: ["prod"],
        sections: [{ id: "section-1", label: "Credentials" }],
        fields: [{ id: "password", purpose: "PASSWORD", value: "secret" }],
        version: 4,
        createdAt: new Date("2026-05-01T10:00:00.000Z"),
        updatedAt: new Date("2026-05-02T10:00:00.000Z"),
      },
      "vault-1",
    ),
    title: "Renamed Database",
    notes: "internal note",
  };

  assert.deepEqual(mapSdkItemToConnectItem(item), {
    id: "item-1",
    title: "Renamed Database",
    vault: { id: "vault-1" },
    category: "LOGIN",
    tags: ["prod"],
    sections: [{ id: "section-1", label: "Credentials" }],
    fields: [
      { id: "password", purpose: "PASSWORD", value: "secret" },
      { id: "notesPlain", purpose: "NOTES", value: "internal note" },
    ],
    version: 4,
    urls: [],
  });
});
