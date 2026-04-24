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
import type { ServerConfig } from "./config.js";

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

  public constructor(
    private readonly config: ServerConfig,
    private readonly clientFactory: ClientFactory = createSdkClient,
  ) {}

  private shouldRefreshClient(error: unknown): boolean {
    if (!(error instanceof Error)) {
      return false;
    }

    return /invalid client id/i.test(error.message);
  }

  private resetClient(): void {
    this.clientPromise = undefined;
  }

  private getClient(): Promise<Client> {
    if (!this.clientPromise) {
      this.clientPromise = this.clientFactory(this.config).catch((error) => {
        this.resetClient();
        throw error;
      });
    }

    return this.clientPromise;
  }

  private async withClient<T>(operation: (client: Client) => Promise<T>): Promise<T> {
    try {
      return await operation(await this.getClient());
    } catch (error) {
      if (!this.shouldRefreshClient(error)) {
        throw error;
      }

      this.resetClient();
      return operation(await this.getClient());
    }
  }

  public async vaultList(params?: VaultListParams): Promise<VaultOverview[]> {
    return this.withClient((client) => client.vaults.list(params));
  }

  public async vaultGetOverview(vaultId: string): Promise<VaultOverview> {
    return this.withClient((client) => client.vaults.getOverview(vaultId));
  }

  public async vaultGet(vaultId: string, params: VaultGetParams): Promise<Vault> {
    return this.withClient((client) => client.vaults.get(vaultId, params));
  }

  public async vaultCreate(params: VaultCreateParams): Promise<Vault> {
    return this.withClient((client) => client.vaults.create(params));
  }

  public async vaultUpdate(vaultId: string, params: VaultUpdateParams): Promise<Vault> {
    return this.withClient((client) => client.vaults.update(vaultId, params));
  }

  public async vaultDelete(vaultId: string): Promise<void> {
    await this.withClient((client) => client.vaults.delete(vaultId));
  }

  public async groupGet(groupId: string, params: GroupGetParams): Promise<Group> {
    return this.withClient((client) => client.groups.get(groupId, params));
  }

  public async vaultGrantGroupPermissions(
    vaultId: string,
    permissions: GroupAccess[],
  ): Promise<void> {
    await this.withClient((client) =>
      client.vaults.grantGroupPermissions(vaultId, permissions),
    );
  }

  public async vaultUpdateGroupPermissions(
    permissions: GroupVaultAccess[],
  ): Promise<void> {
    await this.withClient((client) => client.vaults.updateGroupPermissions(permissions));
  }

  public async vaultRevokeGroupPermissions(
    vaultId: string,
    groupId: string,
  ): Promise<void> {
    await this.withClient((client) =>
      client.vaults.revokeGroupPermissions(vaultId, groupId),
    );
  }

  public async itemList(
    vaultId: string,
    ...filters: ItemListFilter[]
  ): Promise<ItemOverview[]> {
    return this.withClient((client) => client.items.list(vaultId, ...filters));
  }

  public async itemGet(vaultId: string, itemId: string): Promise<Item> {
    return this.withClient((client) => client.items.get(vaultId, itemId));
  }

  public async itemCreate(params: ItemCreateParams): Promise<Item> {
    return this.withClient((client) => client.items.create(params));
  }

  public async itemPut(item: Item): Promise<Item> {
    return this.withClient((client) => client.items.put(item));
  }

  public async itemDelete(vaultId: string, itemId: string): Promise<void> {
    await this.withClient((client) => client.items.delete(vaultId, itemId));
  }

  public async itemArchive(vaultId: string, itemId: string): Promise<void> {
    await this.withClient((client) => client.items.archive(vaultId, itemId));
  }

  public async environmentGetVariables(
    environmentId: string,
  ): Promise<GetVariablesResponse> {
    return this.withClient((client) => client.environments.getVariables(environmentId));
  }

  public async secretResolve(reference: string): Promise<string> {
    return this.withClient((client) => client.secrets.resolve(reference));
  }
}
