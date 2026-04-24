import {
  ARCHIVE_ITEMS,
  CREATE_ITEMS,
  DELETE_ITEMS,
  EXPORT_ITEMS,
  IMPORT_ITEMS,
  MANAGE_VAULT,
  NO_ACCESS,
  PRINT_ITEMS,
  READ_ITEMS,
  RECOVER_VAULT,
  REVEAL_ITEM_PASSWORD,
  SEND_ITEMS,
  UPDATE_ITEMS,
  UPDATE_ITEM_HISTORY,
} from "@1password/sdk";

export const PERMISSION_BITS = {
  RECOVER_VAULT,
  MANAGE_VAULT,
  REVEAL_ITEM_PASSWORD,
  READ_ITEMS,
  UPDATE_ITEMS,
  CREATE_ITEMS,
  ARCHIVE_ITEMS,
  DELETE_ITEMS,
  UPDATE_ITEM_HISTORY,
  SEND_ITEMS,
  IMPORT_ITEMS,
  EXPORT_ITEMS,
  PRINT_ITEMS,
  NO_ACCESS,
} as const;

export type PermissionName = keyof typeof PERMISSION_BITS;

export const PERMISSION_NAMES = Object.keys(PERMISSION_BITS).filter(
  (name) => name !== "NO_ACCESS",
) as PermissionName[];

export function encodePermissions(permissionNames: PermissionName[]): number {
  if (permissionNames.length === 0) {
    return NO_ACCESS;
  }

  return permissionNames.reduce((mask, permissionName) => {
    return mask | PERMISSION_BITS[permissionName];
  }, 0);
}

export function decodePermissions(mask: number): PermissionName[] {
  if (mask === NO_ACCESS) {
    return [];
  }

  return PERMISSION_NAMES.filter((permissionName) => {
    const permissionMask = PERMISSION_BITS[permissionName];
    return (mask & permissionMask) === permissionMask;
  });
}
