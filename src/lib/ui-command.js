import fs from "node:fs/promises";
import path from "node:path";
import { appPaths } from "../constants.js";
import { ensureDirectory } from "./fs-safe.js";

export const DASHBOARD_PAGES = Object.freeze([
  "overview",
  "scan",
  "quarantine",
  "activity",
  "settings"
]);

export function validDashboardPage(value, fallback = null) {
  return DASHBOARD_PAGES.includes(value) ? value : fallback;
}

export async function consumeUiCommand() {
  const commandFile = appPaths().uiCommand;
  let command;
  try {
    command = JSON.parse(await fs.readFile(commandFile, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") await fs.rm(commandFile, { force: true }).catch(() => {});
    return null;
  }

  await ensureDirectory(path.dirname(commandFile));
  await fs.rm(commandFile, { force: true });
  const page = validDashboardPage(command?.page);
  return page ? { page, requestedAt: command.requestedAt || null } : null;
}
