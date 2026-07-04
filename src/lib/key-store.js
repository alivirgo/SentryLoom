import fs from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import { appPaths } from "../constants.js";
import { ensureDirectory } from "./fs-safe.js";

export async function getMasterKey() {
  const paths = appPaths();
  await ensureDirectory(paths.keys);
  try {
    const key = await fs.readFile(paths.masterKey);
    if (key.length !== 32) throw new Error("Master key has an invalid length");
    return key;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const key = crypto.randomBytes(32);
  const temporary = path.join(paths.keys, `master.${process.pid}.tmp`);
  await fs.writeFile(temporary, key, { mode: 0o600, flag: "wx" });
  try {
    await fs.rename(temporary, paths.masterKey);
  } catch (error) {
    await fs.rm(temporary, { force: true });
    if (error.code !== "EEXIST" && error.code !== "EPERM") throw error;
    return fs.readFile(paths.masterKey);
  }
  return key;
}
