using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace UnityDebug
{
    public static class Android
    {
        public static bool TryPrepareConnection(this AndroidDebugBridge adb, out int port, out string error)
        {
            string output;
            int exitCode;

            port = 0;

            output = adb.Run(
                @"shell netstat -lpnt | grep -E '0.0.0.0:56[[:digit:]]{3}' | cut -F 4 | cut -d : -f 2",
                out error,
                out exitCode);

            if (exitCode != 0) {
                return false;
            }

            var ports = output.Split('\n')
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => int.Parse(s.Trim()))
                .ToList();

            if (ports.Count > 1) {
                error = "Multiple potential Unity players detected. Try disconnecting devices or using ANDROID_SERIAL environment variable.";
                return false;
            }
            else if (ports.Count == 0) {
                error = "No Unity players detected.";
                return false;
            }

            port = ports[0];

            output = adb.Run($"forward tcp:{port} tcp:{port}", out error, out exitCode);
            if (exitCode != 0) {
                return false;
            }

            // TODO: Do we need to port to output from 'adb forward'?
            return true;
        }
    }

    public class AndroidDebugBridge
    {
        public string ProgramPath { get; }

        public IDictionary<string, string> Environemnt { get; }

        public AndroidConnectionTarget ConnectionTarget { get; }

        public static AndroidDebugBridge GetAndroidDebugBridge(
            AndroidConnectionTarget connectionTarget,
            IDictionary<string, string> environment = null)
        {
            var adbPath = "adb";
            var isAbsolute = false;

            if (environment != null) {
                if (environment.TryGetValue("ANDROID_SDK_ROOT", out var sdkRoot)) {
                    adbPath = Path.Combine(sdkRoot, "platform-tools", "adb");
                    isAbsolute = true;
                }
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                adbPath = $"{adbPath}.exe";
            }

            if (isAbsolute) {
                if (!File.Exists(adbPath)) {
                    return null;
                }
            }
            else {
                using (var process = new Process()) {
                    process.StartInfo.FileName = adbPath;
                    process.StartInfo.Arguments = "--version";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;

                    try {
                        process.Start();
                        process.StandardOutput.ReadToEnd();
                    }
                    catch {
                        return null;
                    }

                    if (process.ExitCode != 0) {
                        return null;
                    }
                }
            }

            return new AndroidDebugBridge(adbPath, connectionTarget, environment);
        }

        private AndroidDebugBridge(string path,
            AndroidConnectionTarget connectionTarget,
            IDictionary<string, string> environment)
        {
            this.ProgramPath = path;
            this.ConnectionTarget = connectionTarget;
            this.Environemnt = environment;
        }

        public string Run(string arguments, out string error, out int exitCode)
        {
            switch (this.ConnectionTarget) {
                case AndroidConnectionTarget.Ip:
                    arguments = $"-e {arguments}";
                    break;
                case AndroidConnectionTarget.Usb:
                    arguments = $"-d {arguments}";
                    break;
            }

            var startInfo = new ProcessStartInfo(this.ProgramPath, arguments) {
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };

            if (this.Environemnt != null) {
                var env = startInfo.Environment;
                foreach(var kv in this.Environemnt) {
                    if (kv.Value != null) {
                        env[kv.Key] = kv.Value;
                    }
                    else {
                        env.Remove(kv.Key);
                    }
                }
            }

            using (var process = new Process()){
                process.StartInfo = startInfo;

                var errorBuilder = new StringBuilder();
                process.ErrorDataReceived += (sendingProcess, dataEvent) => {
                    if (!string.IsNullOrEmpty(dataEvent.Data)) {
                        errorBuilder.Append(dataEvent.Data);
                    }
                };

                process.Start();
                process.BeginErrorReadLine();
                var output = process.StandardOutput.ReadToEnd();
                error = errorBuilder.ToString();
                exitCode = process.ExitCode;

                return output;
            }
        }
    }

    public enum AndroidConnectionTarget
    {
        Any = 0,
        Ip = 1,
        Usb = 2,
    }
}