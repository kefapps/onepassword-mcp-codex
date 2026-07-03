import {
  type Item,
  type ItemField,
  type ItemSection,
  ItemFieldType,
} from "@1password/sdk";

export const FILL_SENTINEL = "__FILL_ME__";

export const MANAGED_TAG = "mcp-managed";
export const AWAITING_FILL_TAG = "awaiting-fill";
export const PROJECT_TAG_PREFIX = "project:";
export const LINEAR_TAG_PREFIX = "linear:";

export const PROVENANCE_SECTION_ID = "mcp_provenance";
export const PROVENANCE_SECTION_TITLE = "Provenance (MCP)";
export const CREDENTIALS_SECTION_ID = "credentials";
export const CREDENTIALS_SECTION_TITLE = "Credentials";

export const PROVENANCE_FIELD_IDS = {
  project: "mcp_prov_project",
  justification: "mcp_prov_justification",
  ticketId: "mcp_prov_ticket_id",
  ticketUrl: "mcp_prov_ticket_url",
  ticketTitle: "mcp_prov_ticket_title",
  requestedAt: "mcp_prov_requested_at",
  status: "mcp_prov_status",
} as const;

export const STATUS_AWAITING_FILL = "awaiting-fill";

export interface CredentialFieldSpec {
  title: string;
  fieldType?: "Concealed" | "Text";
}

export interface KnownFieldSpec {
  title: string;
  value: string;
}

export interface LinearTicket {
  id?: string;
  url?: string;
  title?: string;
}

export interface ProvenanceInput {
  project: string;
  justification: string;
  ticket?: LinearTicket;
  requestedAt?: Date;
}

function slugify(value: string): string {
  return (
    value
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "item"
  );
}

export function buildManagedTags(
  project: string,
  ticket?: LinearTicket,
  userTags?: string[],
): string[] {
  const tags = [
    MANAGED_TAG,
    AWAITING_FILL_TAG,
    `${PROJECT_TAG_PREFIX}${slugify(project)}`,
  ];
  if (ticket?.id) {
    tags.push(`${LINEAR_TAG_PREFIX}${ticket.id.trim()}`);
  }
  for (const tag of userTags ?? []) {
    const trimmed = tag.trim();
    if (trimmed.length > 0) {
      tags.push(trimmed);
    }
  }
  return [...new Set(tags)];
}

export function buildProvenanceFields(input: ProvenanceInput): ItemField[] {
  const requestedAt = (input.requestedAt ?? new Date()).toISOString();
  const fields: ItemField[] = [
    text(PROVENANCE_FIELD_IDS.project, "project", input.project),
    text(PROVENANCE_FIELD_IDS.justification, "justification", input.justification),
    text(PROVENANCE_FIELD_IDS.requestedAt, "requested_at", requestedAt),
    text(PROVENANCE_FIELD_IDS.status, "status", STATUS_AWAITING_FILL),
  ];
  if (input.ticket?.id) {
    fields.push(text(PROVENANCE_FIELD_IDS.ticketId, "ticket_id", input.ticket.id));
  }
  if (input.ticket?.url) {
    fields.push(text(PROVENANCE_FIELD_IDS.ticketUrl, "ticket_url", input.ticket.url));
  }
  if (input.ticket?.title) {
    fields.push(text(PROVENANCE_FIELD_IDS.ticketTitle, "ticket_title", input.ticket.title));
  }
  return fields;
}

export function buildCredentialFields(
  credentialFields: CredentialFieldSpec[],
  knownFields?: KnownFieldSpec[],
): ItemField[] {
  const usedIds = new Set<string>();
  const fields: ItemField[] = [];

  for (const known of knownFields ?? []) {
    fields.push({
      id: uniqueId(`known_${slugify(known.title)}`, usedIds),
      title: known.title,
      sectionId: CREDENTIALS_SECTION_ID,
      fieldType: ItemFieldType.Text,
      value: known.value,
    });
  }

  for (const spec of credentialFields) {
    fields.push({
      id: uniqueId(`cred_${slugify(spec.title)}`, usedIds),
      title: spec.title,
      sectionId: CREDENTIALS_SECTION_ID,
      fieldType: spec.fieldType === "Text" ? ItemFieldType.Text : ItemFieldType.Concealed,
      value: FILL_SENTINEL,
    });
  }

  return fields;
}

export function requestSections(): ItemSection[] {
  return [
    { id: PROVENANCE_SECTION_ID, title: PROVENANCE_SECTION_TITLE },
    { id: CREDENTIALS_SECTION_ID, title: CREDENTIALS_SECTION_TITLE },
  ];
}

export interface RequestItemSummary {
  id: string;
  title: string;
  vaultId: string;
  project?: string;
  justification?: string;
  ticket?: LinearTicket;
  requestedAt?: string;
  status?: string;
  filled: boolean;
  pendingFieldCount: number;
  createdAt: string;
  updatedAt: string;
  tags: string[];
}

function fieldValue(item: Item, id: string): string | undefined {
  return item.fields.find((field) => field.id === id)?.value;
}

export function summarizeRequestItem(item: Item): RequestItemSummary {
  const pendingFieldCount = item.fields.filter(
    (field) => field.fieldType === ItemFieldType.Concealed && field.value === FILL_SENTINEL,
  ).length;

  const ticketId = fieldValue(item, PROVENANCE_FIELD_IDS.ticketId);
  const ticketUrl = fieldValue(item, PROVENANCE_FIELD_IDS.ticketUrl);
  const ticketTitle = fieldValue(item, PROVENANCE_FIELD_IDS.ticketTitle);
  const ticket =
    ticketId || ticketUrl || ticketTitle
      ? { id: ticketId, url: ticketUrl, title: ticketTitle }
      : undefined;

  return {
    id: item.id,
    title: item.title,
    vaultId: item.vaultId,
    project: fieldValue(item, PROVENANCE_FIELD_IDS.project),
    justification: fieldValue(item, PROVENANCE_FIELD_IDS.justification),
    ticket,
    requestedAt: fieldValue(item, PROVENANCE_FIELD_IDS.requestedAt),
    status: fieldValue(item, PROVENANCE_FIELD_IDS.status),
    filled: pendingFieldCount === 0,
    pendingFieldCount,
    createdAt: item.createdAt.toISOString(),
    updatedAt: item.updatedAt.toISOString(),
    tags: [...item.tags],
  };
}

export function isManagedItem(tags: readonly string[]): boolean {
  return tags.includes(MANAGED_TAG);
}

export function credentialReferences(item: Item): string[] {
  return item.fields
    .filter((field) => field.sectionId === CREDENTIALS_SECTION_ID)
    .map((field) =>
      field.sectionId
        ? `op://${item.vaultId}/${item.id}/${field.sectionId}/${field.id}`
        : `op://${item.vaultId}/${item.id}/${field.id}`,
    );
}

function text(id: string, title: string, value: string): ItemField {
  return {
    id,
    title,
    sectionId: PROVENANCE_SECTION_ID,
    fieldType: ItemFieldType.Text,
    value,
  };
}

function uniqueId(base: string, used: Set<string>): string {
  let candidate = base;
  let counter = 2;
  while (used.has(candidate)) {
    candidate = `${base}_${counter}`;
    counter += 1;
  }
  used.add(candidate);
  return candidate;
}
