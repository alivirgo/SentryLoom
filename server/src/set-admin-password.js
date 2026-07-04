import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { hashAdminPassword } from "./store.js";

const configPath = path.resolve(process.argv[2] || "data/config.json");
const password = String(process.env.SENTRYLOOM_HQ_SETUP_ADMIN_PASSWORD || "");
if (password.length < 12 || password.length > 128) {
  throw new Error("The HQ administrator password must contain 12 to 128 characters");
}

const config = JSON.parse(await fs.readFile(configPath, "utf8"));
const salt = crypto.randomBytes(16).toString("base64");
const iterations = 310000;
config.admin = {
  ...(config.admin || {}),
  iterations,
  salt,
  passwordHash: hashAdminPassword(password, salt, iterations)
};

const temporary = `${configPath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
await fs.writeFile(temporary, `${JSON.stringify(config, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o600,
  flag: "wx"
});
try {
  await fs.rename(temporary, configPath);
} catch (error) {
  await fs.rm(temporary, { force: true }).catch(() => {});
  throw error;
}
console.log("SentryLoom HQ administrator password updated");
