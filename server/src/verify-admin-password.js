import fs from "node:fs/promises";
import path from "node:path";
import { verifyAdminPassword } from "./store.js";

const configPath = path.resolve(process.argv[2] || "data/config.json");
const password = String(process.env.SENTRYLOOM_HQ_SETUP_ADMIN_PASSWORD || "");
if (password.length < 12 || password.length > 128) {
  throw new Error("The HQ administrator password was not supplied correctly");
}

const config = JSON.parse(await fs.readFile(configPath, "utf8"));
if (!config.admin || !verifyAdminPassword(password, config.admin)) {
  throw new Error("The stored HQ administrator password did not pass verification");
}

console.log("SentryLoom HQ administrator password verified");
