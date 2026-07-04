import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";

function powershellPath() {
  if (process.platform !== "win32") return "pwsh";
  const modern = path.join(process.env.ProgramFiles || "C:\\Program Files", "PowerShell", "7", "pwsh.exe");
  return fs.existsSync(modern)
    ? modern
    : path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

export function validatePickerKind(kind) {
  if (kind !== "file" && kind !== "folder") throw new Error("Picker type must be file or folder");
  return kind;
}

function pickerScript(kind) {
  const dialog = kind === "file"
    ? [
        "$dialog = New-Object System.Windows.Forms.OpenFileDialog;",
        "$dialog.Title = 'Select a file to scan';",
        "$dialog.Filter = 'All files (*.*)|*.*';",
        "$dialog.CheckFileExists = $true;",
        "$dialog.Multiselect = $false;",
        "$dialog.RestoreDirectory = $true;"
      ]
    : [
        "$dialog = New-Object System.Windows.Forms.FolderBrowserDialog;",
        "$dialog.Description = 'Select a folder to scan';",
        "$dialog.ShowNewFolderButton = $false;"
      ];
  return [
    "Add-Type -AssemblyName System.Windows.Forms;",
    ...dialog,
    "$owner = New-Object System.Windows.Forms.Form;",
    "$owner.ShowInTaskbar = $false;",
    "$owner.TopMost = $true;",
    "$owner.Opacity = 0;",
    "$owner.Show();",
    "try {",
    "  if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {",
    kind === "file" ? "    [Console]::Out.Write($dialog.FileName);" : "    [Console]::Out.Write($dialog.SelectedPath);",
    "  }",
    "} finally {",
    "  $dialog.Dispose();",
    "  $owner.Close();",
    "  $owner.Dispose();",
    "}"
  ].join(" ");
}

export async function showWindowsPathPicker(kind) {
  validatePickerKind(kind);
  if (process.platform !== "win32") throw new Error("Native path selection is available only on Windows");
  return new Promise((resolve, reject) => {
    execFile(powershellPath(), [
      "-NoLogo", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-Command", pickerScript(kind)
    ], {
      windowsHide: false,
      timeout: 5 * 60 * 1000,
      maxBuffer: 64 * 1024
    }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr.trim() || error.message, { cause: error }));
      else resolve(stdout.trim() || null);
    });
  });
}
