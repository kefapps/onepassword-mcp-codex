import { randomInt } from "node:crypto";
import { type Item, type ItemField, ItemFieldType } from "@1password/sdk";

export type PasswordMode = "provided" | "random" | "memorable";

export interface RandomPasswordOptions {
  length?: number;
  includeLowercase?: boolean;
  includeUppercase?: boolean;
  includeDigits?: boolean;
  includeSymbols?: boolean;
  excludeSimilar?: boolean;
  symbols?: string;
}

export interface MemorablePasswordOptions {
  words?: number;
  separator?: string;
  capitalize?: boolean;
  includeNumber?: boolean;
}

const DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?";
const SIMILAR_CHARACTERS = /[O0Il1]/g;
const MEMORABLE_WORDS = [
  "amber", "anchor", "apple", "apricot", "arch", "arrow", "atlas", "aurora",
  "bamboo", "barn", "beacon", "berry", "birch", "blossom", "bonfire", "breeze",
  "brook", "cabin", "cactus", "canary", "candle", "canyon", "caramel", "cedar",
  "cherry", "cinder", "cliff", "clover", "cobalt", "comet", "copper", "coral",
  "cotton", "cricket", "crimson", "crown", "dahlia", "dawn", "delta", "desert",
  "dolphin", "drift", "ember", "falcon", "fennel", "fern", "fjord", "flame",
  "flint", "flora", "forest", "fossil", "fox", "galaxy", "garden", "glacier",
  "glow", "granite", "grove", "harbor", "harvest", "hazel", "heather", "honey",
  "horizon", "ivy", "jade", "jasmine", "juniper", "kernel", "lagoon", "lantern",
  "laurel", "lavender", "lemon", "lilac", "linen", "lotus", "lunar", "maple",
  "marble", "meadow", "meteor", "mint", "mist", "moon", "moss", "nectar",
  "oasis", "ocean", "olive", "onyx", "opal", "orchid", "otter", "paper",
  "pearl", "pepper", "petal", "pine", "planet", "plum", "prairie", "quartz",
  "quill", "raven", "reef", "river", "robin", "rose", "saffron", "sage",
  "sail", "scarlet", "shadow", "shell", "silver", "sky", "smoke", "solstice",
  "sparrow", "spice", "spring", "spruce", "star", "stone", "sunset", "surf",
  "thistle", "timber", "topaz", "trail", "truffle", "tulip", "valley", "velvet",
  "violet", "wave", "willow", "winter", "wren", "zephyr",
] as const;

function requirePositiveInteger(name: string, value: number, min: number, max: number): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }
}

function shuffle<T>(items: T[]): T[] {
  const next = [...items];
  for (let index = next.length - 1; index > 0; index -= 1) {
    const swapIndex = randomInt(index + 1);
    [next[index], next[swapIndex]] = [next[swapIndex]!, next[index]!];
  }
  return next;
}

function pickOne(source: string): string {
  if (source.length === 0) {
    throw new Error("Cannot choose a character from an empty charset.");
  }
  return source[randomInt(source.length)]!;
}

function pickWord(): string {
  return MEMORABLE_WORDS[randomInt(MEMORABLE_WORDS.length)]!;
}

export function findPasswordField(item: Item, selector = "password"): ItemField {
  const wanted = selector.trim().toLowerCase();
  const match = item.fields.find((field) => {
    const idMatch = field.id.toLowerCase() === wanted;
    const titleMatch = field.title.toLowerCase() === wanted;
    return idMatch || titleMatch;
  });

  if (!match) {
    throw new Error(`Password field ${selector} not found on item ${item.id}.`);
  }

  return match;
}

export function upsertPasswordField(
  item: Item,
  value: string,
  selector = "password",
): Item {
  const wanted = selector.trim();
  const wantedLower = wanted.toLowerCase();
  const nextFields = item.fields.map((field) => ({ ...field }));

  for (const field of nextFields) {
    const idMatch = field.id.toLowerCase() === wantedLower;
    const titleMatch = field.title.toLowerCase() === wantedLower;
    if (idMatch || titleMatch) {
      field.value = value;
      field.fieldType = ItemFieldType.Concealed;
      return {
        ...item,
        fields: nextFields,
      };
    }
  }

  nextFields.push({
    id: wanted,
    title: wanted,
    fieldType: ItemFieldType.Concealed,
    value,
  });
  return {
    ...item,
    fields: nextFields,
  };
}

export function generateRandomPassword(options: RandomPasswordOptions = {}): string {
  const length = options.length ?? 24;
  requirePositiveInteger("length", length, 8, 256);

  const lowercase = "abcdefghijkmnopqrstuvwxyz";
  const uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const digits = "23456789";
  const symbols = options.symbols ?? DEFAULT_SYMBOLS;
  const includeLowercase = options.includeLowercase ?? true;
  const includeUppercase = options.includeUppercase ?? true;
  const includeDigits = options.includeDigits ?? true;
  const includeSymbols = options.includeSymbols ?? true;

  let charsets = [
    includeLowercase ? lowercase : "",
    includeUppercase ? uppercase : "",
    includeDigits ? digits : "",
    includeSymbols ? symbols : "",
  ].filter(Boolean);

  if (options.excludeSimilar) {
    charsets = charsets.map((charset) => charset.replace(SIMILAR_CHARACTERS, ""));
  }

  if (charsets.length === 0) {
    throw new Error("Select at least one character set for random password generation.");
  }

  if (length < charsets.length) {
    throw new Error(
      `length must be at least ${charsets.length} to include one character from each enabled set.`,
    );
  }

  const requiredCharacters = charsets.map((charset) => pickOne(charset));
  const union = charsets.join("");
  const generated = [...requiredCharacters];

  while (generated.length < length) {
    generated.push(pickOne(union));
  }

  return shuffle(generated).join("");
}

export function generateMemorablePassword(
  options: MemorablePasswordOptions = {},
): string {
  const words = options.words ?? 6;
  const separator = options.separator ?? "-";
  const capitalize = options.capitalize ?? false;
  const includeNumber = options.includeNumber ?? true;

  requirePositiveInteger("words", words, 3, 12);

  const parts = Array.from({ length: words }, () => {
    const word = pickWord();
    return capitalize ? `${word[0]!.toUpperCase()}${word.slice(1)}` : word;
  });

  let password = parts.join(separator);
  if (includeNumber) {
    password = `${password}${separator}${randomInt(10)}${randomInt(10)}`;
  }
  return password;
}
