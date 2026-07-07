import { execFile } from "node:child_process";
import { showWindowsPathPicker, validatePickerKind } from "./windows-path-picker.js";

function run(command, args) {
  return new Promise((resolve, reject) => {
    execFile(command, args, {
      windowsHide: false,
      timeout: 5 * 60 * 1000,
      maxBuffer: 64 * 1024,
      encoding: "utf8"
    }, (error, stdout, stderr) => {
      if (error) reject(new Error(String(stderr || "").trim() || error.message, { cause: error }));
      else resolve(String(stdout || "").trim() || null);
    });
  });
}

export async function showPlatformPathPicker(kind) {
  validatePickerKind(kind);
  if (process.platform === "win32") return showWindowsPathPicker(kind);
  if (process.platform === "darwin") {
    const noun = kind === "file" ? "file" : "folder";
    const script = `POSIX path of (choose ${noun} with prompt "Select a ${noun} to scan")`;
    return run("osascript", ["-e", script]);
  }
  return run("zenity", [
    "--file-selection",
    ...(kind === "folder" ? ["--directory"] : []),
    "--title", `Select a ${kind} to scan`
  ]);
}
