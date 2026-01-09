const MULTIPLIERS_MS: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
};

export function durationStringToMs(
  input: string | number | undefined,
  defaultMs: number,
): number {
  if (typeof input === 'number') {
    return input;
  }

  if (!input) {
    return defaultMs;
  }

  if (/^\d+$/.test(input)) {
    return Number(input);
  }

  const match = input.trim().match(/^(\d+)(ms|s|m|h|d)$/i);
  if (!match) {
    throw new Error(
      `Invalid duration string "${input}". Use values like 900, 15m, 1h, 7d, etc.`,
    );
  }

  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  return value * MULTIPLIERS_MS[unit];
}

export function durationStringToSeconds(
  input: string | number | undefined,
  defaultSeconds: number,
): number {
  const ms = durationStringToMs(input, defaultSeconds * 1000);
  return Math.round(ms / 1000);
}
