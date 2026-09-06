using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Talos.Sdk
{
    /// <summary>
    /// A machine fingerprint: the composite the server matches on, plus the
    /// per-component hashes that let it tolerate hardware drift.
    /// </summary>
    public sealed class FingerprintData
    {
        /// <summary>The composite, derived from <see cref="Components"/>.</summary>
        public string Composite { get; }

        /// <summary>Per-component hashes, <c>{component_id: hash}</c>.</summary>
        public IReadOnlyDictionary<string, string> Components { get; }

        internal FingerprintData(string composite, IReadOnlyDictionary<string, string> components)
        {
            Composite = composite;
            Components = components;
        }
    }

    /// <summary>
    /// Collects a machine fingerprint.
    /// <para>
    /// Every component is HMAC'd with a product-scoped key before it leaves the
    /// machine, so the server stores hashes and never the underlying serials —
    /// and the same hardware yields different hashes for different products.
    /// </para>
    /// <para>
    /// Two things this deliberately does <b>not</b> do: it never launches a
    /// subprocess (<c>wmic</c>/<c>ioreg</c>/<c>dmidecode</c> draw antivirus
    /// attention, break in sandboxes, and are slow), and it never takes a
    /// dependency outside the BCL. That bounds what is readable per platform —
    /// see <c>docs/FINGERPRINT.md</c> for the coverage table. Where the reachable
    /// components are too weak to match on, the server simply keeps using exact
    /// matching; supply <see cref="TalosOptions.ExtraFingerprintComponents"/> if
    /// your app can read more than the BCL can.
    /// </para>
    /// <para>
    /// None of this resists a determined attacker: the values are produced on the
    /// client, so they can be forged. It exists to recognise honest hardware
    /// churn, not to stop piracy.
    /// </para>
    /// </summary>
    public static class Fingerprint
    {
        /// <summary>
        /// Collect the fingerprint for a product. A component that cannot be read
        /// is simply absent — never an error, and never a fabricated value.
        /// </summary>
        /// <param name="productToken">Scopes the hashing key to this product.</param>
        /// <param name="extra">
        /// Host-supplied components merged over the collected ones, for platforms
        /// where the BCL cannot reach the hardware.
        /// </param>
        public static FingerprintData Collect(
            string productToken,
            IReadOnlyDictionary<string, string>? extra = null)
        {
            byte[] key;
            using (var sha = SHA256.Create())
            {
                key = sha.ComputeHash(Encoding.UTF8.GetBytes("talos-fp|" + (productToken ?? "")));
            }

            var raw = new SortedDictionary<string, string>(StringComparer.Ordinal);
            Add(raw, "machine_guid", MachineGuid());
            Add(raw, "smbios_uuid", ReadFile("/sys/class/dmi/id/product_uuid"));
            Add(raw, "disk_serial", DiskSerial());
            Add(raw, "mac_set", MacSet());
            Add(raw, "cpu", Cpu());
            Add(raw, "mem_bucket", MemBucket());
            Add(raw, "os_install", OsInstall());
            Add(raw, "hostname", Safe(() => Environment.MachineName));

            if (extra != null)
            {
                foreach (var kv in extra) Add(raw, kv.Key, kv.Value);
            }

            var hashed = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in raw)
            {
                hashed[kv.Key] = Hmac(key, kv.Key + "=" + kv.Value);
            }

            // The composite is a digest of the hashed components, so a host that
            // reports the same parts always produces the same composite and the
            // exact-match fast path keeps working.
            var canonical = string.Join("\n", hashed.Select(kv => kv.Key + "=" + kv.Value));
            string composite;
            using (var sha = SHA256.Create())
            {
                composite = "fp2:" + ToHex(sha.ComputeHash(Encoding.UTF8.GetBytes(canonical)));
            }
            return new FingerprintData(composite, hashed);
        }

        private static void Add(IDictionary<string, string> into, string id, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value)) into[id] = value!.Trim();
        }

        private static string Hmac(byte[] key, string value)
        {
            using (var mac = new HMACSHA256(key))
            {
                // 16 bytes is plenty to distinguish components and keeps the
                // request small; this is a matching token, not a secret.
                return ToHex(mac.ComputeHash(Encoding.UTF8.GetBytes(value))).Substring(0, 32);
            }
        }

        // ---- component sources -------------------------------------------------

        private static bool IsWindows()
        {
#if NET8_0_OR_GREATER
            return OperatingSystem.IsWindows();
#else
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
#endif
        }

        /// <summary>Per-install OS identity: survives hardware changes.</summary>
        private static string? MachineGuid()
        {
            if (IsWindows()) return ReadRegistry(@"SOFTWARE\Microsoft\Cryptography", "MachineGuid");
            return ReadFile("/etc/machine-id") ?? ReadFile("/var/lib/dbus/machine-id");
        }

        private static string? DiskSerial()
        {
            if (IsWindows())
            {
                var serial = SystemVolumeSerial();
                return serial == 0 ? null : serial.ToString("x8", CultureInfo.InvariantCulture);
            }
            // Root-only on most distributions; absent is a normal outcome.
            return ReadFile("/sys/class/dmi/id/board_serial");
        }

        /// <summary>Sorted physical MACs. Excludes loopback and tunnels, which
        /// churn constantly and would report drift on every VPN connection.</summary>
        private static string? MacSet()
        {
            return Safe(() =>
            {
                var macs = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                             && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    .Select(n => n.GetPhysicalAddress().ToString())
                    .Where(m => !string.IsNullOrEmpty(m) && m.Trim('0').Length > 0)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(m => m, StringComparer.Ordinal)
                    .ToList();
                return macs.Count == 0 ? null : string.Join(",", macs);
            });
        }

        private static string? Cpu()
        {
            string? model = IsWindows()
                ? Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER")
                : ProcCpuModel();
            if (string.IsNullOrEmpty(model)) return null;
            return model + "|" + Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture);
        }

        private static string? ProcCpuModel()
        {
            var text = ReadFile("/proc/cpuinfo");
            if (text == null) return null;
            foreach (var line in text.Split('\n'))
            {
                if (!line.StartsWith("model name", StringComparison.Ordinal)) continue;
                int colon = line.IndexOf(':');
                if (colon >= 0) return line.Substring(colon + 1).Trim();
            }
            return null;
        }

        /// <summary>Installed RAM rounded down to a power of two GiB. Coarse on
        /// purpose: exact byte counts shift with firmware reserving memory, which
        /// would look like drift on a machine nobody touched.</summary>
        private static string? MemBucket()
        {
            long bytes = 0;
            if (IsWindows())
            {
                // The generic overload, not Marshal.SizeOf(Type): the Type one
                // builds marshalling code at run time, which a NativeAOT
                // application does not have. Both give the same number here.
                var status = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
                if (Safe(() => GlobalMemoryStatusEx(ref status))) bytes = (long)status.ullTotalPhys;
            }
            else
            {
                var text = ReadFile("/proc/meminfo");
                if (text != null)
                {
                    foreach (var line in text.Split('\n'))
                    {
                        if (!line.StartsWith("MemTotal:", StringComparison.Ordinal)) continue;
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && long.TryParse(parts[1], out long kb)) bytes = kb * 1024;
                        break;
                    }
                }
            }
            if (bytes <= 0) return null;
            long gib = bytes / (1024L * 1024L * 1024L);
            long bucket = 1;
            while (bucket * 2 <= gib) bucket *= 2;
            return bucket.ToString(CultureInfo.InvariantCulture);
        }

        private static string? OsInstall()
        {
            if (!IsWindows()) return null;
            return ReadRegistry(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "InstallDate");
        }

        // ---- platform plumbing -------------------------------------------------

        private static string? ReadRegistry(string path, string name)
        {
            return Safe(() =>
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path))
                {
                    return key?.GetValue(name)?.ToString();
                }
            });
        }

        private static string? ReadFile(string path)
        {
            return Safe(() =>
            {
                if (!System.IO.File.Exists(path)) return null;
                var text = System.IO.File.ReadAllText(path).Trim();
                return text.Length == 0 ? null : text;
            });
        }

        private static uint SystemVolumeSerial()
        {
            return Safe(() =>
            {
                string root = System.IO.Path.GetPathRoot(Environment.SystemDirectory) ?? "";
                if (root.Length == 0) return 0u;
                uint serial;
                var volume = new StringBuilder(261);
                var fsName = new StringBuilder(261);
                bool ok = GetVolumeInformation(root, volume, volume.Capacity, out serial,
                                               out _, out _, fsName, fsName.Capacity);
                return ok ? serial : 0u;
            });
        }

        /// <summary>Run a probe, treating any failure as "component unavailable".
        /// A missing component costs a little matching weight; a thrown exception
        /// from a licensing call would cost the user their session.</summary>
        private static T? Safe<T>(Func<T?> f) where T : class
        {
            try { return f(); } catch { return null; }
        }

        private static uint Safe(Func<uint> f)
        {
            try { return f(); } catch { return 0u; }
        }

        private static bool Safe(Func<bool> f)
        {
            try { return f(); } catch { return false; }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeInformation(
            string rootPathName,
            StringBuilder volumeNameBuffer, int volumeNameSize,
            out uint volumeSerialNumber,
            out uint maximumComponentLength,
            out uint fileSystemFlags,
            StringBuilder fileSystemNameBuffer, int fileSystemNameSize);

        private static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
    }
}
