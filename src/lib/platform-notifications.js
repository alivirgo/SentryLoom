import { spawn } from "node:child_process";
import { notificationForEvent, showDetectionNotification as showWindowsNotification } from "./windows-notifications.js";

export { notificationForEvent };

function detached(command, args) {
  const child = spawn(command, args, { detached: true, stdio: "ignore", windowsHide: true });
  child.on("error", () => {});
  child.unref();
  return true;
}

export function showDetectionNotification(notification) {
  if (!notification) return false;
  if (process.platform === "win32") return showWindowsNotification(notification);
  const title = String(notification.title || "SentryLoom").slice(0, 100);
  const message = String(notification.message || "").slice(0, 500);
  if (process.platform === "darwin") {
    const escaped = (value) => value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
    return detached("osascript", [
      "-e", `display notification "${escaped(message)}" with title "${escaped(title)}"`
    ]);
  }
  return detached("notify-send", ["--app-name=SentryLoom", title, message]);
}
