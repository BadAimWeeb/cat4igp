export type Mode = "light" | "dark";
export const themeKey = "cat4igp-theme";

export function preferredMode(
  storage: Pick<Storage, "getItem">,
  dark: boolean,
): Mode {
  try {
    const saved = storage.getItem(themeKey);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    // Storage may be unavailable; system preference still works.
  }
  return dark ? "dark" : "light";
}
