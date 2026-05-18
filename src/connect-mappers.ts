import {
  AutofillBehavior,
  ItemCategory,
  ItemFieldType,
  ItemState,
  VaultType,
  type Item,
  type ItemCreateParams,
  type ItemField,
  type ItemOverview,
  type ItemSection,
  type Vault,
  type VaultOverview,
  type Website,
} from "@1password/sdk";

export interface ConnectVault {
  id?: string;
  name?: string;
  description?: string;
  type?: string;
  items?: number;
  contentVersion?: number;
  attributeVersion?: number;
  createdAt?: Date | string;
  updatedAt?: Date | string;
}

export interface ConnectItemUrl {
  href?: string;
  label?: string;
  primary?: boolean;
}

export interface ConnectItemSectionRef {
  id?: string;
}

export interface ConnectItemSection {
  id?: string;
  label?: string;
}

export interface ConnectItemField {
  id?: string;
  section?: ConnectItemSectionRef;
  type?: string;
  purpose?: string;
  label?: string;
  value?: string;
  otp?: string;
}

export interface ConnectItem {
  id?: string;
  title?: string;
  vault?: { id?: string };
  category?: string;
  urls?: ConnectItemUrl[];
  favorite?: boolean;
  tags?: string[];
  version?: number;
  trashed?: boolean;
  createdAt?: Date | string;
  updatedAt?: Date | string;
  sections?: ConnectItemSection[];
  fields?: ConnectItemField[];
}

function toDate(value: Date | string | undefined): Date {
  if (value instanceof Date) {
    return value;
  }
  return value ? new Date(value) : new Date(0);
}

function requiredString(value: string | undefined, fallback: string): string {
  return value && value.length > 0 ? value : fallback;
}

function mapVaultType(type: string | undefined): VaultType {
  switch (type) {
    case "PERSONAL":
      return VaultType.Personal;
    case "EVERYONE":
      return VaultType.Everyone;
    case "TRANSFER":
      return VaultType.Transfer;
    case "USER_CREATED":
      return VaultType.UserCreated;
    default:
      return VaultType.Unsupported;
  }
}

function mapItemCategory(category: string | undefined): ItemCategory {
  switch (category) {
    case "LOGIN":
      return ItemCategory.Login;
    case "PASSWORD":
      return ItemCategory.Password;
    case "API_CREDENTIAL":
      return ItemCategory.ApiCredentials;
    case "SERVER":
      return ItemCategory.Server;
    case "DATABASE":
      return ItemCategory.Database;
    case "CREDIT_CARD":
      return ItemCategory.CreditCard;
    case "MEMBERSHIP":
      return ItemCategory.Membership;
    case "PASSPORT":
      return ItemCategory.Passport;
    case "SOFTWARE_LICENSE":
      return ItemCategory.SoftwareLicense;
    case "OUTDOOR_LICENSE":
      return ItemCategory.OutdoorLicense;
    case "SECURE_NOTE":
      return ItemCategory.SecureNote;
    case "WIRELESS_ROUTER":
      return ItemCategory.Router;
    case "BANK_ACCOUNT":
      return ItemCategory.BankAccount;
    case "DRIVER_LICENSE":
      return ItemCategory.DriverLicense;
    case "IDENTITY":
      return ItemCategory.Identity;
    case "REWARD_PROGRAM":
      return ItemCategory.Rewards;
    case "EMAIL_ACCOUNT":
      return ItemCategory.Email;
    case "SOCIAL_SECURITY_NUMBER":
      return ItemCategory.SocialSecurityNumber;
    case "MEDICAL_RECORD":
      return ItemCategory.MedicalRecord;
    case "SSH_KEY":
      return ItemCategory.SshKey;
    case "DOCUMENT":
      return ItemCategory.Document;
    default:
      return ItemCategory.Unsupported;
  }
}

function toConnectCategory(category: ItemCategory): string {
  switch (category) {
    case ItemCategory.Login:
      return "LOGIN";
    case ItemCategory.Password:
      return "PASSWORD";
    case ItemCategory.ApiCredentials:
      return "API_CREDENTIAL";
    case ItemCategory.Server:
      return "SERVER";
    case ItemCategory.Database:
      return "DATABASE";
    case ItemCategory.CreditCard:
      return "CREDIT_CARD";
    case ItemCategory.Membership:
      return "MEMBERSHIP";
    case ItemCategory.Passport:
      return "PASSPORT";
    case ItemCategory.SoftwareLicense:
      return "SOFTWARE_LICENSE";
    case ItemCategory.OutdoorLicense:
      return "OUTDOOR_LICENSE";
    case ItemCategory.SecureNote:
      return "SECURE_NOTE";
    case ItemCategory.Router:
      return "WIRELESS_ROUTER";
    case ItemCategory.BankAccount:
      return "BANK_ACCOUNT";
    case ItemCategory.DriverLicense:
      return "DRIVER_LICENSE";
    case ItemCategory.Identity:
      return "IDENTITY";
    case ItemCategory.Rewards:
      return "REWARD_PROGRAM";
    case ItemCategory.Email:
      return "EMAIL_ACCOUNT";
    case ItemCategory.SocialSecurityNumber:
      return "SOCIAL_SECURITY_NUMBER";
    case ItemCategory.MedicalRecord:
      return "MEDICAL_RECORD";
    case ItemCategory.SshKey:
      return "SSH_KEY";
    case ItemCategory.Document:
      return "DOCUMENT";
    default:
      throw new Error(`Unsupported 1Password item category for Connect: ${category}`);
  }
}

function mapConnectFieldType(field: ConnectItemField): ItemFieldType {
  if (field.purpose === "PASSWORD") {
    return ItemFieldType.Concealed;
  }
  if (field.purpose === "USERNAME" || field.purpose === "NOTES") {
    return ItemFieldType.Text;
  }

  switch (field.type) {
    case "CONCEALED":
      return ItemFieldType.Concealed;
    case "EMAIL":
      return ItemFieldType.Email;
    case "URL":
      return ItemFieldType.Url;
    case "OTP":
      return ItemFieldType.Totp;
    case "DATE":
      return ItemFieldType.Date;
    case "MONTH_YEAR":
      return ItemFieldType.MonthYear;
    case "MENU":
      return ItemFieldType.Menu;
    case "STRING":
      return ItemFieldType.Text;
    default:
      return ItemFieldType.Unsupported;
  }
}

function toConnectFieldType(fieldType: ItemFieldType): string {
  switch (fieldType) {
    case ItemFieldType.Concealed:
      return "CONCEALED";
    case ItemFieldType.Email:
      return "EMAIL";
    case ItemFieldType.Url:
      return "URL";
    case ItemFieldType.Totp:
      return "OTP";
    case ItemFieldType.Date:
      return "DATE";
    case ItemFieldType.MonthYear:
      return "MONTH_YEAR";
    case ItemFieldType.Menu:
      return "MENU";
    default:
      return "STRING";
  }
}

function builtInPurpose(field: ItemField): "USERNAME" | "PASSWORD" | "NOTES" | undefined {
  const key = field.id.trim().toLowerCase();
  const title = field.title.trim().toLowerCase();
  if (key === "username" || title === "username") {
    return "USERNAME";
  }
  if (key === "password" || title === "password") {
    return "PASSWORD";
  }
  if (key === "notesplain" || key === "notes" || title === "notes") {
    return "NOTES";
  }
  return undefined;
}

function fieldTitle(field: ConnectItemField, index: number): string {
  if (field.label) {
    return field.label;
  }
  if (field.purpose) {
    return field.purpose.toLowerCase();
  }
  return field.id ?? field.type?.toLowerCase() ?? `field-${index + 1}`;
}

export function mapConnectVaultToVaultOverview(vault: ConnectVault): VaultOverview {
  return {
    id: requiredString(vault.id, ""),
    title: requiredString(vault.name, ""),
    description: vault.description ?? "",
    vaultType: mapVaultType(vault.type),
    activeItemCount: vault.items ?? 0,
    contentVersion: vault.contentVersion ?? 0,
    attributeVersion: vault.attributeVersion ?? 0,
    createdAt: toDate(vault.createdAt),
    updatedAt: toDate(vault.updatedAt),
  };
}

export function mapConnectVaultToVault(vault: ConnectVault): Vault {
  const overview = mapConnectVaultToVaultOverview(vault);
  return {
    id: overview.id,
    title: overview.title,
    description: overview.description,
    vaultType: overview.vaultType,
    activeItemCount: overview.activeItemCount,
    contentVersion: overview.contentVersion,
    attributeVersion: overview.attributeVersion,
    access: [],
  };
}

function mapConnectUrls(urls: ConnectItemUrl[] | undefined): Website[] {
  return (urls ?? []).map((url) => ({
    url: requiredString(url.href, ""),
    label: url.label ?? "website",
    autofillBehavior: AutofillBehavior.ExactDomain,
  }));
}

function mapSdkWebsites(websites: Website[] | undefined): ConnectItemUrl[] {
  return (websites ?? []).map((website, index) => ({
    href: website.url,
    label: website.label,
    primary: index === 0,
  }));
}

export function mapConnectItemToItemOverview(
  item: ConnectItem,
  vaultId: string,
): ItemOverview {
  return {
    id: requiredString(item.id, ""),
    title: requiredString(item.title, ""),
    category: mapItemCategory(item.category),
    vaultId: item.vault?.id ?? vaultId,
    websites: mapConnectUrls(item.urls),
    tags: item.tags ?? [],
    createdAt: toDate(item.createdAt),
    updatedAt: toDate(item.updatedAt),
    state: item.trashed ? ItemState.Archived : ItemState.Active,
  };
}

function mapConnectSections(sections: ConnectItemSection[] | undefined): ItemSection[] {
  return (sections ?? []).map((section) => ({
    id: requiredString(section.id, ""),
    title: section.label ?? "",
  }));
}

function mapSdkSections(sections: ItemSection[] | undefined): ConnectItemSection[] {
  return (sections ?? []).map((section) => ({
    id: section.id,
    label: section.title,
  }));
}

function mapConnectField(field: ConnectItemField, index: number): ItemField | undefined {
  if (field.purpose === "NOTES") {
    return undefined;
  }

  const fieldType = mapConnectFieldType(field);
  const value = field.value ?? field.otp ?? "";
  const mapped: ItemField = {
    id: requiredString(field.id, fieldTitle(field, index)),
    title: fieldTitle(field, index),
    fieldType,
    value,
  };
  if (field.section?.id) {
    mapped.sectionId = field.section.id;
  }

  if (fieldType === ItemFieldType.Totp) {
    mapped.details = { type: "Otp", content: { code: field.otp } };
  }

  return mapped;
}

function mapConnectFields(fields: ConnectItemField[] | undefined): ItemField[] {
  return (fields ?? [])
    .map((field, index) => mapConnectField(field, index))
    .filter((field): field is ItemField => field !== undefined);
}

function connectNotes(fields: ConnectItemField[] | undefined): string {
  return fields?.find((field) => field.purpose === "NOTES")?.value ?? "";
}

export function mapConnectFullItemToItem(item: ConnectItem, vaultId: string): Item {
  return {
    id: requiredString(item.id, ""),
    title: requiredString(item.title, ""),
    category: mapItemCategory(item.category),
    vaultId: item.vault?.id ?? vaultId,
    fields: mapConnectFields(item.fields),
    sections: mapConnectSections(item.sections),
    notes: connectNotes(item.fields),
    tags: item.tags ?? [],
    websites: mapConnectUrls(item.urls),
    version: item.version ?? 0,
    files: [],
    createdAt: toDate(item.createdAt),
    updatedAt: toDate(item.updatedAt),
  };
}

function mapSdkField(field: ItemField): ConnectItemField {
  const purpose = builtInPurpose(field);
  if (purpose) {
    return {
      id: field.id,
      purpose,
      value: field.value,
    };
  }

  return {
    id: field.id,
    label: field.title,
    section: field.sectionId ? { id: field.sectionId } : undefined,
    type: toConnectFieldType(field.fieldType),
    value: field.value,
  };
}

function appendNotes(fields: ConnectItemField[], notes: string | undefined): ConnectItemField[] {
  if (!notes) {
    return fields;
  }

  return [...fields, { id: "notesPlain", purpose: "NOTES", value: notes }];
}

export function mapSdkItemCreateParamsToConnectItem(
  params: ItemCreateParams,
): ConnectItem {
  return {
    title: params.title,
    vault: { id: params.vaultId },
    category: toConnectCategory(params.category),
    tags: params.tags ?? [],
    sections: mapSdkSections(params.sections),
    fields: appendNotes((params.fields ?? []).map(mapSdkField), params.notes),
    urls: mapSdkWebsites(params.websites),
  };
}

export function mapSdkItemToConnectItem(item: Item): ConnectItem {
  return {
    id: item.id,
    title: item.title,
    vault: { id: item.vaultId },
    category: toConnectCategory(item.category),
    tags: item.tags,
    sections: mapSdkSections(item.sections),
    fields: appendNotes(item.fields.map(mapSdkField), item.notes),
    version: item.version,
    urls: mapSdkWebsites(item.websites),
  };
}
