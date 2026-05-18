import { OnePasswordConnect } from "@1password/connect";
import type {
  GetVariablesResponse,
  Group,
  GroupAccess,
  GroupGetParams,
  GroupVaultAccess,
  Item,
  ItemCreateParams,
  ItemListFilter,
  ItemOverview,
  Vault,
  VaultCreateParams,
  VaultGetParams,
  VaultListParams,
  VaultOverview,
  VaultUpdateParams,
} from "@1password/sdk";
import type { AuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import {
  mapConnectFullItemToItem,
  mapConnectItemToItemOverview,
  mapConnectVaultToVault,
  mapConnectVaultToVaultOverview,
  mapSdkItemCreateParamsToConnectItem,
  mapSdkItemToConnectItem,
  type ConnectItem,
  type ConnectItemField,
  type ConnectItemSection,
  type ConnectVault,
} from "./connect-mappers.js";
import {
  recordDiagnosticAudit,
  type RuntimeDiagnostics,
} from "./diagnostics.js";
import type { OnePasswordService } from "./service.js";

export interface ConnectClient {
  listVaults(): Promise<unknown[]>;
  getVault(vaultQuery: string): Promise<unknown>;
  listItems(vaultId: string): Promise<unknown[]>;
  getItem(vaultId: string, itemQuery: string): Promise<unknown>;
  createItem(vaultId: string, item: unknown): Promise<unknown>;
  updateItem(vaultId: string, item: unknown): Promise<unknown>;
  deleteItem(vaultId: string, itemQuery: string): Promise<void>;
}

type ConnectClientFactory = (config: ServerConfig) => Promise<ConnectClient>;

function createConnectClient(config: ServerConfig): Promise<ConnectClient> {
  return Promise.resolve(
    OnePasswordConnect({
      serverURL: config.connectHost!,
      token: config.connectToken!,
      timeout: config.connectTimeoutMs,
    }) as ConnectClient,
  );
}

function unsupportedConnectOperation(operation: string): never {
  throw new Error(`${operation} is not supported in Connect mode.`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function equalsIdentifier(candidate: string | undefined, wanted: string): boolean {
  return candidate?.trim().toLowerCase() === wanted.trim().toLowerCase();
}

function decodeReferencePathSegment(segment: string): string {
  return decodeURIComponent(segment.replace(/\+/g, "%20"));
}

function parseSecretReference(reference: string): {
  vaultQuery: string;
  itemQuery: string;
  sectionQuery?: string;
  fieldQuery: string;
  attribute: string;
} {
  let url: URL;
  try {
    url = new URL(reference);
  } catch {
    throw new Error(`Invalid 1Password secret reference: ${reference}`);
  }

  if (url.protocol !== "op:") {
    throw new Error(`Invalid 1Password secret reference protocol: ${reference}`);
  }

  const pathParts = url.pathname
    .split("/")
    .filter(Boolean)
    .map(decodeReferencePathSegment);
  if (url.hostname.length === 0 || (pathParts.length !== 2 && pathParts.length !== 3)) {
    throw new Error("Secret reference must use op://vault/item/[section/]field.");
  }

  const attribute = url.searchParams.get("attribute") ?? url.searchParams.get("attr") ?? "value";
  if (!["value", "id", "type", "purpose", "otp"].includes(attribute)) {
    throw new Error(`Unsupported Connect secret reference attribute: ${attribute}`);
  }

  return {
    vaultQuery: decodeReferencePathSegment(url.hostname),
    itemQuery: pathParts[0]!,
    sectionQuery: pathParts.length === 3 ? pathParts[1] : undefined,
    fieldQuery: pathParts[pathParts.length - 1]!,
    attribute,
  };
}

function fieldPurposeName(field: ConnectItemField): string | undefined {
  return field.purpose?.toLowerCase();
}

function fieldTypeForPurpose(field: ConnectItemField): string | undefined {
  if (field.type) {
    return field.type;
  }
  if (field.purpose === "PASSWORD") {
    return "CONCEALED";
  }
  if (field.purpose === "USERNAME" || field.purpose === "NOTES") {
    return "STRING";
  }
  return undefined;
}

function fieldMatches(field: ConnectItemField, wanted: string): boolean {
  return [
    field.id,
    field.label,
    field.purpose,
    fieldPurposeName(field),
    field.type,
    field.type?.toLowerCase(),
  ].some((candidate) => equalsIdentifier(candidate, wanted));
}

function sectionMatches(section: ConnectItemSection, wanted: string): boolean {
  return [section.id, section.label].some((candidate) => equalsIdentifier(candidate, wanted));
}

function sectionIdForQuery(
  sections: ConnectItemSection[] | undefined,
  sectionQuery: string | undefined,
): string | undefined {
  if (!sectionQuery) {
    return undefined;
  }

  const matches = (sections ?? []).filter((section) => sectionMatches(section, sectionQuery));
  if (matches.length === 0) {
    throw new Error(`Section ${sectionQuery} not found.`);
  }
  if (matches.length > 1) {
    throw new Error(`Section ${sectionQuery} matched more than once.`);
  }
  return matches[0]!.id;
}

function resolveField(item: ConnectItem, sectionQuery: string | undefined, fieldQuery: string) {
  const sectionId = sectionIdForQuery(item.sections, sectionQuery);
  const fields = (item.fields ?? []).filter((field) => {
    const matchesSection = sectionId ? field.section?.id === sectionId : !field.section?.id;
    return matchesSection && fieldMatches(field, fieldQuery);
  });

  if (fields.length === 0) {
    throw new Error(`Field ${fieldQuery} not found.`);
  }
  if (fields.length > 1) {
    throw new Error(`Field ${fieldQuery} matched more than once.`);
  }
  return fields[0]!;
}

function fieldAttribute(field: ConnectItemField, attribute: string): string {
  switch (attribute) {
    case "value":
      return field.value ?? field.otp ?? "";
    case "id":
      return field.id ?? "";
    case "type":
      return fieldTypeForPurpose(field) ?? "";
    case "purpose":
      return field.purpose ?? "";
    case "otp":
      return field.otp ?? "";
    default:
      throw new Error(`Unsupported Connect secret reference attribute: ${attribute}`);
  }
}

function filterItemsByState(
  items: ItemOverview[],
  filters: ItemListFilter[],
): ItemOverview[] {
  const stateFilter = filters.find((filter) => filter.type === "ByState");
  if (!stateFilter) {
    return items.filter((item) => item.state === "active");
  }

  return items.filter((item) => {
    if (item.state === "active") {
      return stateFilter.content.active;
    }
    return stateFilter.content.archived;
  });
}

export class ConnectOnePasswordService implements OnePasswordService {
  private clientPromise?: Promise<ConnectClient>;
  private connectClientCreated = false;
  private lastConnectAuthAttemptAt?: string;
  private lastConnectAuthOutcome?: "success" | "error";
  private lastConnectOperation?: string;

  public constructor(
    private readonly config: ServerConfig,
    private readonly clientFactory: ConnectClientFactory = createConnectClient,
    private readonly auditLogger?: AuditLogger,
  ) {}

  public runtimeDiagnostics(): RuntimeDiagnostics {
    return {
      backend: "connect",
      connectClientCreated: this.connectClientCreated,
      lastConnectAuthAttemptAt: this.lastConnectAuthAttemptAt,
      lastConnectAuthOutcome: this.lastConnectAuthOutcome,
      lastConnectOperation: this.lastConnectOperation,
    };
  }

  private recordDiagnostic(
    action: string,
    outcome: "success" | "error",
    metadata: Record<string, unknown>,
    error?: unknown,
  ): void {
    if (!this.auditLogger) {
      return;
    }
    recordDiagnosticAudit(this.config, this.auditLogger, action, outcome, metadata, error);
  }

  private getClient(triggerOperation: string): Promise<ConnectClient> {
    if (!this.clientPromise) {
      this.lastConnectAuthAttemptAt = new Date().toISOString();
      this.recordDiagnostic("op_connect_client_create_start", "success", {
        triggerOperation,
        connectHost: this.config.connectHost,
      });
      this.clientPromise = this.clientFactory(this.config)
        .then((client) => {
          this.connectClientCreated = true;
          this.lastConnectAuthOutcome = "success";
          this.recordDiagnostic("op_connect_client_create", "success", {
            triggerOperation,
            connectHost: this.config.connectHost,
          });
          return client;
        })
        .catch((error: unknown) => {
          this.lastConnectAuthOutcome = "error";
          this.clientPromise = undefined;
          this.recordDiagnostic(
            "op_connect_client_create",
            "error",
            { triggerOperation, connectHost: this.config.connectHost },
            error,
          );
          throw error;
        });
    }
    return this.clientPromise;
  }

  private async withClient<T>(
    operationName: string,
    operation: (client: ConnectClient) => Promise<T>,
  ): Promise<T> {
    this.lastConnectOperation = operationName;
    const startedAt = Date.now();
    try {
      const client = await this.getClient(operationName);
      const result = await operation(client);
      this.recordDiagnostic("op_connect_operation", "success", {
        operation: operationName,
        durationMs: Date.now() - startedAt,
      });
      return result;
    } catch (error) {
      this.recordDiagnostic(
        "op_connect_operation",
        "error",
        { operation: operationName, durationMs: Date.now() - startedAt },
        error,
      );
      throw error;
    }
  }

  public async vaultList(_params?: VaultListParams): Promise<VaultOverview[]> {
    return this.withClient("vault_list", async (client) =>
      (await client.listVaults()).map((vault) =>
        mapConnectVaultToVaultOverview(vault as ConnectVault),
      ),
    );
  }

  public async vaultGetOverview(vaultId: string): Promise<VaultOverview> {
    return this.withClient("vault_get_overview", async (client) =>
      mapConnectVaultToVaultOverview((await client.getVault(vaultId)) as ConnectVault),
    );
  }

  public async vaultGet(vaultId: string, _params: VaultGetParams): Promise<Vault> {
    return this.withClient("vault_get", async (client) =>
      mapConnectVaultToVault((await client.getVault(vaultId)) as ConnectVault),
    );
  }

  public async vaultCreate(_params: VaultCreateParams): Promise<Vault> {
    unsupportedConnectOperation("vaultCreate");
  }

  public async vaultUpdate(_vaultId: string, _params: VaultUpdateParams): Promise<Vault> {
    unsupportedConnectOperation("vaultUpdate");
  }

  public async vaultDelete(_vaultId: string): Promise<void> {
    unsupportedConnectOperation("vaultDelete");
  }

  public async groupGet(_groupId: string, _params: GroupGetParams): Promise<Group> {
    unsupportedConnectOperation("groupGet");
  }

  public async vaultGrantGroupPermissions(
    _vaultId: string,
    _permissions: GroupAccess[],
  ): Promise<void> {
    unsupportedConnectOperation("vaultGrantGroupPermissions");
  }

  public async vaultUpdateGroupPermissions(
    _permissions: GroupVaultAccess[],
  ): Promise<void> {
    unsupportedConnectOperation("vaultUpdateGroupPermissions");
  }

  public async vaultRevokeGroupPermissions(
    _vaultId: string,
    _groupId: string,
  ): Promise<void> {
    unsupportedConnectOperation("vaultRevokeGroupPermissions");
  }

  public async itemList(
    vaultId: string,
    ...filters: ItemListFilter[]
  ): Promise<ItemOverview[]> {
    return this.withClient("item_list", async (client) => {
      const items = (await client.listItems(vaultId)).map((item) =>
        mapConnectItemToItemOverview(item as ConnectItem, vaultId),
      );
      return filterItemsByState(items, filters);
    });
  }

  public async itemGet(vaultId: string, itemId: string): Promise<Item> {
    return this.withClient("item_get", async (client) =>
      mapConnectFullItemToItem((await client.getItem(vaultId, itemId)) as ConnectItem, vaultId),
    );
  }

  public async itemCreate(params: ItemCreateParams): Promise<Item> {
    return this.withClient("item_create", async (client) =>
      mapConnectFullItemToItem(
        (await client.createItem(
          params.vaultId,
          mapSdkItemCreateParamsToConnectItem(params),
        )) as ConnectItem,
        params.vaultId,
      ),
    );
  }

  public async itemPut(item: Item): Promise<Item> {
    return this.withClient("item_put", async (client) =>
      mapConnectFullItemToItem(
        (await client.updateItem(item.vaultId, mapSdkItemToConnectItem(item))) as ConnectItem,
        item.vaultId,
      ),
    );
  }

  public async itemDelete(vaultId: string, itemId: string): Promise<void> {
    return this.withClient("item_delete", async (client) => {
      await client.deleteItem(vaultId, itemId);
    });
  }

  public async itemArchive(_vaultId: string, _itemId: string): Promise<void> {
    unsupportedConnectOperation("itemArchive");
  }

  public async environmentGetVariables(
    _environmentId: string,
  ): Promise<GetVariablesResponse> {
    unsupportedConnectOperation("environmentGetVariables");
  }

  public async secretResolve(reference: string): Promise<string> {
    return this.withClient("secret_resolve", async (client) => {
      const parsed = parseSecretReference(reference);
      const vault = (await client.getVault(parsed.vaultQuery)) as ConnectVault;
      const vaultId = requiredConnectId(vault, "vault");
      const item = (await client.getItem(vaultId, parsed.itemQuery)) as ConnectItem;
      const field = resolveField(item, parsed.sectionQuery, parsed.fieldQuery);
      return fieldAttribute(field, parsed.attribute);
    });
  }
}

function requiredConnectId(value: unknown, resource: string): string {
  if (!isRecord(value) || typeof value.id !== "string" || value.id.length === 0) {
    throw new Error(`Connect ${resource} response did not include an id.`);
  }
  return value.id;
}
