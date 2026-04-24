import {
  type Item,
  type ItemField,
  type ItemOverview,
  type Vault,
  type VaultAccess,
  type Website,
  ItemFieldType,
} from "@1password/sdk";
import { decodePermissions } from "./permissions.js";

export interface RedactedField {
  id: string;
  title: string;
  sectionId?: string;
  fieldType: ItemFieldType;
  valueState: "redacted";
  detailsSummary?: string;
}

export interface RedactedItemMetadata {
  id: string;
  title: string;
  category: Item["category"];
  vaultId: string;
  tags: string[];
  websites: Website[];
  sections: Item["sections"];
  notesState: "redacted" | "empty";
  fields: RedactedField[];
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface RedactedVaultAccess {
  vaultUuid: string;
  accessorType: VaultAccess["accessorType"];
  accessorUuid: string;
  permissionsMask: number;
  permissions: string[];
}

export interface RedactedVault {
  id: string;
  title: string;
  description: string;
  vaultType: Vault["vaultType"];
  activeItemCount: number;
  contentVersion: number;
  attributeVersion: number;
  access?: RedactedVaultAccess[];
}

function summarizeFieldDetails(field: ItemField): string | undefined {
  if (field.details?.type === "Otp") {
    return field.details.content.code ? "otp-available" : "otp-unavailable";
  }

  if (field.details?.type === "SshKey") {
    return field.details.content?.keyType ?? "ssh-key";
  }

  if (field.details?.type === "Address") {
    return field.details.content?.country ?? "address";
  }

  return undefined;
}

export function redactField(field: ItemField): RedactedField {
  return {
    id: field.id,
    title: field.title,
    sectionId: field.sectionId,
    fieldType: field.fieldType,
    valueState: "redacted",
    detailsSummary: summarizeFieldDetails(field),
  };
}

export function redactItem(item: Item): RedactedItemMetadata {
  return {
    id: item.id,
    title: item.title,
    category: item.category,
    vaultId: item.vaultId,
    tags: [...item.tags],
    websites: [...item.websites],
    sections: [...item.sections],
    notesState: item.notes ? "redacted" : "empty",
    fields: item.fields.map(redactField),
    version: item.version,
    createdAt: item.createdAt.toISOString(),
    updatedAt: item.updatedAt.toISOString(),
  };
}

export interface RedactedItemOverview {
  id: string;
  title: string;
  category: ItemOverview["category"];
  vaultId: string;
  websites: Website[];
  tags: string[];
  createdAt: string;
  updatedAt: string;
  state: ItemOverview["state"];
}

export function redactItemOverview(item: ItemOverview): RedactedItemOverview {
  return {
    id: item.id,
    title: item.title,
    category: item.category,
    vaultId: item.vaultId,
    websites: [...item.websites],
    tags: [...item.tags],
    createdAt: item.createdAt.toISOString(),
    updatedAt: item.updatedAt.toISOString(),
    state: item.state,
  };
}

export function redactVault(vault: Vault): RedactedVault {
  return {
    id: vault.id,
    title: vault.title,
    description: vault.description,
    vaultType: vault.vaultType,
    activeItemCount: vault.activeItemCount,
    contentVersion: vault.contentVersion,
    attributeVersion: vault.attributeVersion,
    access: vault.access?.map((access) => ({
      vaultUuid: access.vaultUuid,
      accessorType: access.accessorType,
      accessorUuid: access.accessorUuid,
      permissionsMask: access.permissions,
      permissions: decodePermissions(access.permissions),
    })),
  };
}
