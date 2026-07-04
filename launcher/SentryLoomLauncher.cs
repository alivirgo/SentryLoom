using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

[assembly: AssemblyTitle("SentryLoom Endpoint Security")]
[assembly: AssemblyDescription("SentryLoom native security console launcher")]
[assembly: AssemblyCompany("NUC7 Studios")]
[assembly: AssemblyProduct("SentryLoom Endpoint Security")]
[assembly: AssemblyCopyright("Copyright (c) 2026 NUC7 Studios")]
[assembly: AssemblyVersion("0.16.3.0")]
[assembly: AssemblyFileVersion("0.16.3.0")]
[assembly: ComVisible(false)]

namespace NUC7Studios.SentryLoom
{
    internal static class Program
    {
        private const string MutexName = "Local\\NUC7Studios.SentryLoom.Console";
        private const string BackgroundMutexName = "Local\\NUC7Studios.SentryLoom.Background";
        private static readonly object LogLock = new object();
        private delegate bool EnumWindowsCallback(IntPtr window, IntPtr parameter);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsCallback callback, IntPtr parameter);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr window);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr window, StringBuilder text, int maximum);

        [DllImport("user32.dll")]
        private static extern bool ShowWindowAsync(IntPtr window, int command);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr window);

        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr icon);

        private static string DataDirectory()
        {
            string configured = Environment.GetEnvironmentVariable("SENTRYLOOM_DATA_DIR");
            if (!String.IsNullOrWhiteSpace(configured))
                return Path.GetFullPath(configured);
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SentryLoom");
        }

        private static string RequestedPage(string[] arguments)
        {
            foreach (string argument in arguments)
            {
                if (!argument.StartsWith("--page=", StringComparison.OrdinalIgnoreCase)) continue;
                string page = argument.Substring("--page=".Length).ToLowerInvariant();
                if (page == "overview" || page == "scan" || page == "quarantine" ||
                    page == "activity" || page == "settings")
                    return page;
            }
            return null;
        }

        private static void RelayNavigation(string page)
        {
            string dataDirectory = DataDirectory();
            Directory.CreateDirectory(dataDirectory);
            string destination = Path.Combine(dataDirectory, "ui-command.json");
            string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
            string json = "{\"page\":\"" + page + "\",\"requestedAt\":\"" +
                DateTime.UtcNow.ToString("o") + "\"}";
            File.WriteAllText(temporary, json);
            if (File.Exists(destination)) File.Delete(destination);
            File.Move(temporary, destination);
        }

        private static bool BringConsoleToFront()
        {
            IntPtr match = IntPtr.Zero;
            EnumWindows(delegate(IntPtr window, IntPtr parameter)
            {
                if (!IsWindowVisible(window)) return true;
                var title = new StringBuilder(512);
                GetWindowText(window, title, title.Capacity);
                if (title.ToString().IndexOf(
                    "SentryLoom Endpoint Security",
                    StringComparison.OrdinalIgnoreCase) < 0) return true;
                match = window;
                return false;
            }, IntPtr.Zero);
            if (match == IntPtr.Zero) return false;
            ShowWindowAsync(match, 9);
            SetForegroundWindow(match);
            return true;
        }

        private static string EdgeExecutable()
        {
            string[] candidates = {
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft", "Edge", "Application", "msedge.exe")
            };
            foreach (string candidate in candidates)
                if (File.Exists(candidate)) return candidate;
            return null;
        }

        private static bool ReopenConsole(string page)
        {
            string runtime = Path.Combine(DataDirectory(), "dashboard-runtime.txt");
            if (!File.Exists(runtime)) return false;
            string baseUrl = File.ReadAllText(runtime).Trim();
            Uri dashboardUri;
            if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out dashboardUri) ||
                dashboardUri.Scheme != Uri.UriSchemeHttp ||
                !dashboardUri.IsLoopback)
                return false;
            string url = baseUrl + "&page=" + Uri.EscapeDataString(page ?? "overview");
            string edge = EdgeExecutable();
            Process.Start(new ProcessStartInfo
            {
                FileName = edge ?? "rundll32.exe",
                Arguments = edge != null
                    ? "--app=\"" + url + "\" --no-first-run --disable-features=msEdgeSidebarV2"
                    : "url.dll,FileProtocolHandler \"" + url + "\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            });
            return true;
        }

        private static void OpenOrStartConsole(string page)
        {
            RelayNavigation(page);
            if (BringConsoleToFront() || ReopenConsole(page)) return;
            Process.Start(new ProcessStartInfo
            {
                FileName = Assembly.GetExecutingAssembly().Location,
                Arguments = "--page=" + (page ?? "overview"),
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            });
        }

        private static Icon StatusIcon(Color color)
        {
            using (var bitmap = new Bitmap(16, 16))
            using (Graphics graphics = Graphics.FromImage(bitmap))
            using (var brush = new SolidBrush(color))
            using (var border = new Pen(Color.White, 1))
            {
                graphics.Clear(Color.Transparent);
                graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                graphics.FillEllipse(brush, 2, 2, 12, 12);
                graphics.DrawEllipse(border, 2, 2, 12, 12);
                IntPtr handle = bitmap.GetHicon();
                try { return (Icon)Icon.FromHandle(handle).Clone(); }
                finally { DestroyIcon(handle); }
            }
        }

        private static string LogDirectory()
        {
            return Path.Combine(DataDirectory(), "logs");
        }

        private static string OutputLog()
        {
            return Path.Combine(LogDirectory(), "background-output.log");
        }

        private static void RotateOutputLog()
        {
            lock (LogLock)
            {
                Directory.CreateDirectory(LogDirectory());
                string current = OutputLog();
                string previous = Path.Combine(LogDirectory(), "background-output.previous.log");
                if (!File.Exists(current) || new FileInfo(current).Length < 2 * 1024 * 1024) return;
                if (File.Exists(previous)) File.Delete(previous);
                File.Move(current, previous);
            }
        }

        private static void AppendOutput(string channel, string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return;
            lock (LogLock)
            {
                Directory.CreateDirectory(LogDirectory());
                if (File.Exists(OutputLog()) &&
                    new FileInfo(OutputLog()).Length >= 4 * 1024 * 1024)
                    RotateOutputLog();
                File.AppendAllText(
                    OutputLog(),
                    DateTime.UtcNow.ToString("o") + " [" + channel + "] " + value + Environment.NewLine,
                    Encoding.UTF8);
            }
        }

        private static Process StartWorker(string arguments)
        {
            string applicationDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string node = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "nodejs",
                "node.exe");
            string cli = Path.Combine(applicationDirectory, "src", "cli.js");
            if (!File.Exists(node))
                throw new FileNotFoundException("The required Node.js runtime is missing.", node);
            if (!File.Exists(cli))
                throw new FileNotFoundException("The SentryLoom application files are incomplete.", cli);
            RotateOutputLog();
            var start = new ProcessStartInfo
            {
                FileName = node,
                Arguments = "--disable-warning=ExperimentalWarning \"" + cli + "\" " + arguments,
                WorkingDirectory = applicationDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            Process child = new Process();
            child.StartInfo = start;
            child.EnableRaisingEvents = true;
            child.OutputDataReceived += delegate(object sender, DataReceivedEventArgs eventArgs)
            {
                AppendOutput("stdout", eventArgs.Data);
            };
            child.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs eventArgs)
            {
                AppendOutput("stderr", eventArgs.Data);
            };
            if (!child.Start())
                throw new InvalidOperationException("Windows could not start the SentryLoom worker.");
            child.BeginOutputReadLine();
            child.BeginErrorReadLine();
            return child;
        }

        private static bool HqConnected()
        {
            string stateFile = Path.Combine(DataDirectory(), "hq-connector-state.json");
            try
            {
                string state = File.ReadAllText(stateFile);
                bool running = Regex.IsMatch(state, "\"running\"\\s*:\\s*true", RegexOptions.IgnoreCase);
                bool connected = Regex.IsMatch(state, "\"connected\"\\s*:\\s*true", RegexOptions.IgnoreCase);
                Match updated = Regex.Match(state, "\"updatedAt\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
                DateTime updatedAt;
                if (!running || !connected || !updated.Success ||
                    !DateTime.TryParse(updated.Groups[1].Value, out updatedAt))
                    return false;
                return DateTime.UtcNow - updatedAt.ToUniversalTime() < TimeSpan.FromSeconds(60);
            }
            catch { return false; }
        }

        private static void WriteBackgroundRuntime(Process child)
        {
            string destination = Path.Combine(DataDirectory(), "background-runtime.json");
            string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
            Directory.CreateDirectory(DataDirectory());
            string json = "{\"launcherPid\":" + Process.GetCurrentProcess().Id +
                ",\"workerPid\":" + child.Id +
                ",\"updatedAt\":\"" + DateTime.UtcNow.ToString("o") + "\"}";
            File.WriteAllText(temporary, json, Encoding.UTF8);
            if (File.Exists(destination)) File.Delete(destination);
            File.Move(temporary, destination);
        }

        private static int RunBackground()
        {
            bool createdNew;
            using (var instance = new Mutex(true, BackgroundMutexName, out createdNew))
            {
                if (!createdNew) return 0;
                Icon green = StatusIcon(Color.FromArgb(35, 176, 92));
                Icon red = StatusIcon(Color.FromArgb(210, 55, 65));
                var tray = new NotifyIcon();
                var menu = new ContextMenuStrip();
                var open = new ToolStripMenuItem("Open SentryLoom");
                var output = new ToolStripMenuItem("View background output");
                open.Click += delegate { OpenOrStartConsole("overview"); };
                output.Click += delegate { OpenOrStartConsole("activity"); };
                menu.Items.Add(open);
                menu.Items.Add(output);
                tray.ContextMenuStrip = menu;
                tray.Icon = red;
                tray.Text = "SentryLoom HQ unreachable";
                tray.Visible = true;
                tray.DoubleClick += delegate { OpenOrStartConsole("overview"); };
                Process child = null;
                var timer = new System.Windows.Forms.Timer();
                timer.Interval = 3000;
                timer.Tick += delegate
                {
                    if (child == null || child.HasExited)
                    {
                        Application.ExitThread();
                        return;
                    }
                    bool connected = HqConnected();
                    tray.Icon = connected ? green : red;
                    tray.Text = connected
                        ? "SentryLoom HQ connected"
                        : "SentryLoom HQ unreachable";
                    try { WriteBackgroundRuntime(child); } catch {}
                };
                try
                {
                    AppendOutput("system", "Starting resident protection");
                    child = StartWorker("protect");
                    WriteBackgroundRuntime(child);
                    timer.Start();
                    Application.Run();
                    child.WaitForExit();
                    AppendOutput("system", "Resident protection exited with code " + child.ExitCode);
                    return child.ExitCode;
                }
                finally
                {
                    timer.Stop();
                    timer.Dispose();
                    tray.Visible = false;
                    tray.Dispose();
                    menu.Dispose();
                    green.Dispose();
                    red.Dispose();
                    try
                    {
                        File.Delete(Path.Combine(DataDirectory(), "background-runtime.json"));
                    }
                    catch {}
                    if (child != null) child.Dispose();
                    try { instance.ReleaseMutex(); } catch (ApplicationException) { }
                }
            }
        }

        private static int RunOneShot(string command)
        {
            Process child = StartWorker(command);
            try
            {
                child.WaitForExit();
                return child.ExitCode;
            }
            finally { child.Dispose(); }
        }

        [STAThread]
        private static int Main(string[] arguments)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            foreach (string argument in arguments)
            {
                if (argument.Equals("--background", StringComparison.OrdinalIgnoreCase))
                {
                    try { return RunBackground(); }
                    catch (Exception error)
                    {
                        AppendOutput("fatal", error.ToString());
                        return 1;
                    }
                }
                if (argument.StartsWith("--command=", StringComparison.OrdinalIgnoreCase))
                {
                    string command = argument.Substring("--command=".Length).ToLowerInvariant();
                    if (command != "quick" && command != "full")
                    {
                        AppendOutput("fatal", "Unsupported background command: " + command);
                        return 1;
                    }
                    try { return RunOneShot(command); }
                    catch (Exception error)
                    {
                        AppendOutput("fatal", error.ToString());
                        return 1;
                    }
                }
            }
            string requestedPage = RequestedPage(arguments);

            bool createdNew;
            using (var instance = new Mutex(true, MutexName, out createdNew))
            {
                if (!createdNew)
                {
                    string page = requestedPage ?? "overview";
                    RelayNavigation(page);
                    if (!BringConsoleToFront() && !ReopenConsole(page))
                        MessageBox.Show(
                            "SentryLoom is running, but its console could not be restored. Wait a moment and try again.",
                            "SentryLoom Endpoint Security",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                    return 0;
                }

                try
                {
                    string applicationDirectory = AppDomain.CurrentDomain.BaseDirectory;
                    string node = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                        "nodejs",
                        "node.exe");
                    string cli = Path.Combine(applicationDirectory, "src", "cli.js");

                    if (!File.Exists(node))
                        throw new FileNotFoundException("The required Node.js runtime is missing.", node);
                    if (!File.Exists(cli))
                        throw new FileNotFoundException("The SentryLoom application files are incomplete.", cli);

                    var start = new ProcessStartInfo
                    {
                        FileName = node,
                        Arguments = "--disable-warning=ExperimentalWarning \"" + cli + "\" dashboard" +
                            (requestedPage == null ? "" : " --page " + requestedPage),
                        WorkingDirectory = applicationDirectory,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };

                    using (Process child = Process.Start(start))
                    {
                        if (child == null)
                            throw new InvalidOperationException("Windows could not start the SentryLoom console.");
                        child.WaitForExit();
                        if (child.ExitCode != 0)
                        {
                            MessageBox.Show(
                                "The SentryLoom console stopped unexpectedly. Restart it or run Repair from Setup.",
                                "SentryLoom Endpoint Security",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
                        }
                        return child.ExitCode;
                    }
                }
                catch (Exception error)
                {
                    MessageBox.Show(
                        error.Message,
                        "SentryLoom could not start",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return 1;
                }
                finally
                {
                    try { instance.ReleaseMutex(); } catch (ApplicationException) { }
                }
            }
        }
    }
}
