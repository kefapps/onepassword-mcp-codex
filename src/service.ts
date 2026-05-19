import {
  type Client,
  type GetVariablesResponse,
  type Group,
  type GroupAccess,
  type GroupGetParams,
  type GroupVaultAccess,
  type Item,
  type ItemCreateParams,
  type ItemListFilter,
  type ItemOverview,
  type Vault,
  type VaultCreateParams,
  type VaultGetParams,
  type VaultListParams,
  type VaultOverview,
  type VaultUpdateParams,
  DesktopAuth,
  createClient,
} from "@1password/sdk";
import type { AuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import {
  recordDiagnosticAudit,
  type RuntimeDiagnostics,
} from "./diagnostics.js";
import { errorMessage, normalizeError } from "./errors.js";

type ClientFactory = (config: ServerConfig) => Promise<Client>;

export interface OnePasswordService {
  vaultList(params?: VaultListParams): Promise<VaultOverview[]>;
  vaultGetOverview(vaultId: string): Promise<VaultOverview>;
  vaultGet(vaultId: string, params: VaultGetParams): Promise<Vault>;
  vaultCreate(params: VaultCreateParams): Promise<Vault>;
  vaultUpdate(vaultId: string, params: VaultUpdateParams): Promise<Vault>;
  vaultDelete(vaultId: string): Promise<void>;
  groupGet(groupId: string, params: GroupGetParams): Promise<Group>;
  vaultGrantGroupPermissions(vaultId: string, permissions: GroupAccess[]): Promise<void>;
  vaultUpdateGroupPermissions(permissions: GroupVaultAccess[]): Promise<void>;
  vaultRevokeGroupPermissions(vaultId: string, groupId: string): Promise<void>;
  itemList(vaultId: string, ...filters: ItemListFilter[]): Promise<ItemOverview[]>;
  itemGet(vaultId: string, itemId: string): Promise<Item>;
  itemCreate(params: ItemCreateParams): Promise<Item>;
  itemPut(item: Item): Promise<Item>;
  itemDelete(vaultId: string, itemId: string): Promise<void>;
  itemArchive(vaultId: string, itemId: string): Promise<void>;
  environmentGetVariables(environmentId: string): Promise<GetVariablesResponse>;
  secretResolve(reference: string): Promise<string>;
}

function createSdkClient(config: ServerConfig): Promise<Client> {
  const auth =
    config.authMode === "desktop"
      ? new DesktopAuth(config.account!)
      : config.serviceAccountToken!;

  return createClient({
    auth,
    integrationName: config.integrationName,
    integrationVersion: config.integrationVersion,
  });
}

export class SdkOnePasswordService implements OnePasswordService {
  private clientPromise?: Promise<Client>;
  private sdkClientCreated = false;
  private lastSdkAuthAttemptAt?: string;
  private lastSdkAuthOutcome?: "success" | "error";
  private lastSdkOperation?: string;

  public constructor(
    private readonly config: ServerConfig,
    private readonly clientFactory: ClientFactory = createSdkClient,
    private readonly auditLogger?: AuditLogger,
  ) {}

  public runtimeDiagnostics(): RuntimeDiagnostics {
    return {
      backend: "sdk",
      sdkClientCreated: this.sdkClientCreated,
      lastSdkAuthAttemptAt: this.lastSdkAuthAttemptAt,
      lastSdkAuthOutcome: this.lastSdkAuthOutcome,
      lastSdkOperation: this.lastSdkOperation,
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

  private shouldRefreshClient(error: unknown): boolean {
    return /invalid client id/i.test(errorMessage(error));
  }

  private resetClient(): void {
    this.clientPromise = undefined;
    this.sdkClientCreated = false;
  }

  private getClient(triggerOperation: string): Promise<Client> {
    if (!this.clientPromise) {
      this.lastSdkAuthAttemptAt = new Date().toISOString();
      this.lastSdkOperation = triggerOperation;
      this.recordDiagnostic("op_sdk_client_create_start", "success", {
        triggerOperation,
        authMode: this.config.authMode,
        accountConfigured: Boolean(this.config.account),
        serviceAccountTokenConfigured: Boolean(this.config.serviceAccountToken),
      });
      this.clientPromise = this.clientFactory(this.config)
        .then((client) => {
          this.sdkClientCreated = true;
          this.lastSdkAuthOutcome = "success";
          this.recordDiagnostic("op_sdk_client_create", "success", {
            triggerOperation,
            authMode: this.config.authMode,
          });
          return client;
        })
        .catch((error) => {
          const normalizedError = normalizeError(error);
          this.lastSdkAuthOutcome = "error";
          this.recordDiagnostic("op_sdk_client_create", "error", {
            triggerOperation,
            authMode: this.config.authMode,
          }, normalizedError);
          this.resetClient();
          throw normalizedError;
        });
    }

    return this.clientPromise;
  }

  private async withClient<T>(
    operationName: string,
    operation: (client: Client) => Promise<T>,
  ): Promise<T> {
    const startedAt = Date.now();
    this.lastSdkOperation = operationName;
    try {
      const result = await operation(await this.getClient(operationName));
      this.recordDiagnostic("op_sdk_operation", "success", {
        operation: operationName,
        durationMs: Date.now() - startedAt,
        sdkClientCreated: this.sdkClientCreated,
      });
      return result;
    } catch (error) {
      const normalizedError = normalizeError(error);
      if (!this.shouldRefreshClient(normalizedError)) {
        this.recordDiagnostic("op_sdk_operation", "error", {
          operation: operationName,
          durationMs: Date.now() - startedAt,
          sdkClientCreated: this.sdkClientCreated,
          retried: false,
        }, normalizedError);
        throw normalizedError;
      }

      this.resetClient();
      try {
        const result = await operation(await this.getClient(operationName));
        this.recordDiagnostic("op_sdk_operation", "success", {
          operation: operationName,
          durationMs: Date.now() - startedAt,
          sdkClientCreated: this.sdkClientCreated,
          retried: true,
        });
        return result;
      } catch (retryError) {
        const normalizedRetryError = normalizeError(retryError);
        this.recordDiagnostic("op_sdk_operation", "error", {
          operation: operationName,
          durationMs: Date.now() - startedAt,
          sdkClientCreated: this.sdkClientCreated,
          retried: true,
        }, normalizedRetryError);
        throw normalizedRetryError;
      }
    }
  }

  public async vaultList(params?: VaultListParams): Promise<VaultOverview[]> {
    return this.withClient("vault_list", (client) => client.vaults.list(params));
  }

  public async vaultGetOverview(vaultId: string): Promise<VaultOverview> {
    return this.withClient("vault_get_overview", (client) =>
      client.vaults.getOverview(vaultId),
    );
  }

  public async vaultGet(vaultId: string, params: VaultGetParams): Promise<Vault> {
    return this.withClient("vault_get", (client) =>
      client.vaults.get(vaultId, params),
    );
  }

  public async vaultCreate(params: VaultCreateParams): Promise<Vault> {
    return this.withClient("vault_create", (client) => client.vaults.create(params));
  }

  public async vaultUpdate(vaultId: string, params: VaultUpdateParams): Promise<Vault> {
    return this.withClient("vault_update", (client) =>
      client.vaults.update(vaultId, params),
    );
  }

  public async vaultDelete(vaultId: string): Promise<void> {
    await this.withClient("vault_delete", (client) => client.vaults.delete(vaultId));
  }

  public async groupGet(groupId: string, params: GroupGetParams): Promise<Group> {
    return this.withClient("group_get", (client) => client.groups.get(groupId, params));
  }

  public async vaultGrantGroupPermissions(
    vaultId: string,
    permissions: GroupAccess[],
  ): Promise<void> {
    await this.withClient("vault_grant_group_permissions", (client) =>
      client.vaults.grantGroupPermissions(vaultId, permissions),
    );
  }

  public async vaultUpdateGroupPermissions(
    permissions: GroupVaultAccess[],
  ): Promise<void> {
    await this.withClient("vault_update_group_permissions", (client) =>
      client.vaults.updateGroupPermissions(permissions),
    );
  }

  public async vaultRevokeGroupPermissions(
    vaultId: string,
    groupId: string,
  ): Promise<void> {
    await this.withClient("vault_revoke_group_permissions", (client) =>
      client.vaults.revokeGroupPermissions(vaultId, groupId),
    );
  }

  public async itemList(
    vaultId: string,
    ...filters: ItemListFilter[]
  ): Promise<ItemOverview[]> {
    return this.withClient("item_list", (client) =>
      client.items.list(vaultId, ...filters),
    );
  }

  public async itemGet(vaultId: string, itemId: string): Promise<Item> {
    return this.withClient("item_get", (client) => client.items.get(vaultId, itemId));
  }

  public async itemCreate(params: ItemCreateParams): Promise<Item> {
    return this.withClient("item_create", (client) => client.items.create(params));
  }

  public async itemPut(item: Item): Promise<Item> {
    return this.withClient("item_put", (client) => client.items.put(item));
  }

  public async itemDelete(vaultId: string, itemId: string): Promise<void> {
    await this.withClient("item_delete", (client) =>
      client.items.delete(vaultId, itemId),
    );
  }

  public async itemArchive(vaultId: string, itemId: string): Promise<void> {
    await this.withClient("item_archive", (client) =>
      client.items.archive(vaultId, itemId),
    );
  }

  public async environmentGetVariables(
    environmentId: string,
  ): Promise<GetVariablesResponse> {
    return this.withClient("environment_get_variables", (client) =>
      client.environments.getVariables(environmentId),
    );
  }

  public async secretResolve(reference: string): Promise<string> {
    return this.withClient("secret_resolve", (client) =>
      client.secrets.resolve(reference),
    );
  }
}
