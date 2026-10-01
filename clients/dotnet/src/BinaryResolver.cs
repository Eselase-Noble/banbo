using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Banbo
{
    /// <summary>
    /// Resolves (and if necessary downloads) the banbo CLI binary for the current host,
    /// caches it under the user's local application data, and executes it.
    /// </summary>
    /// <remarks>
    /// Resolution order:
    /// <list type="number">
    ///   <item>The <c>BANBO_BINARY</c> environment variable, if set to an existing file.</item>
    ///   <item>A previously cached download for this version.</item>
    ///   <item>A fresh download + extract from the GitHub release.</item>
    /// </list>
    /// </remarks>
    public static class BinaryResolver
    {
        /// <summary>GitHub repository owner.</summary>
        public const string Owner = "Eselase-Noble";

        /// <summary>GitHub repository name (also the binary name).</summary>
        public const string Repo = "banbo";

        /// <summary>The banbo release version this client pins to.</summary>
        public const string Version = "0.1.3";

        private static readonly object CacheLock = new object();

        // Single shared HttpClient; GitHub release downloads redirect to a CDN.
        private static readonly HttpClient Http = CreateHttpClient();

        private static HttpClient CreateHttpClient()
        {
            var client = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd($"banbo-dotnet/{Version}");
            return client;
        }

        /// <summary>
        /// Resolves the absolute path to an executable banbo binary, downloading and
        /// extracting it on first use.
        /// </summary>
        /// <exception cref="BanboException">If the host is unsupported or the download fails.</exception>
        public static string Resolve()
            => ResolveAsync(CancellationToken.None).GetAwaiter().GetResult();

        /// <summary>
        /// Asynchronously resolves the absolute path to an executable banbo binary,
        /// downloading and extracting it on first use.
        /// </summary>
        /// <exception cref="BanboException">If the host is unsupported or the download fails.</exception>
        public static async Task<string> ResolveAsync(CancellationToken cancellationToken = default)
        {
            var overridePath = Environment.GetEnvironmentVariable("BANBO_BINARY");
            if (!string.IsNullOrWhiteSpace(overridePath))
            {
                if (!File.Exists(overridePath))
                {
                    throw new BanboException(
                        $"BANBO_BINARY is set to \"{overridePath}\" but that file does not exist.");
                }
                return overridePath!;
            }

            var target = DetectTarget();
            var binaryPath = Path.Combine(CacheDir(), target.Exe);

            if (File.Exists(binaryPath))
            {
                return binaryPath;
            }

            await DownloadAndExtractAsync(target, binaryPath, cancellationToken).ConfigureAwait(false);
            return binaryPath;
        }

        /// <summary>Per-version cache directory under LocalApplicationData/banbo/&lt;version&gt;.</summary>
        public static string CacheDir()
        {
            var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(baseDir))
            {
                // Some headless *nix environments return empty; fall back to a temp-based path.
                baseDir = Path.Combine(Path.GetTempPath(), "banbo-cache");
            }
            return Path.Combine(baseDir, "banbo", Version);
        }

        /// <summary>Resolves the current host to the banbo release tokens.</summary>
        /// <exception cref="BanboException">If the OS or architecture is unsupported.</exception>
        public static Target DetectTarget()
        {
            string? os = null;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) os = "linux";
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) os = "darwin";
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) os = "windows";

            string? arch;
            switch (RuntimeInformation.OSArchitecture)
            {
                case Architecture.X64:
                    arch = "amd64";
                    break;
                case Architecture.Arm64:
                    arch = "arm64";
                    break;
                default:
                    arch = null;
                    break;
            }

            if (os == null || arch == null)
            {
                throw new BanboException(
                    $"Unsupported platform \"{RuntimeInformation.OSDescription} / {RuntimeInformation.OSArchitecture}\". " +
                    "Prebuilt banbo binaries are available for linux, darwin and windows on amd64 and arm64. " +
                    "You can point banbo at a locally built binary with the BANBO_BINARY environment variable.");
            }

            var ext = os == "windows" ? "zip" : "tar.gz";
            var exe = os == "windows" ? "banbo.exe" : "banbo";
            return new Target(os, arch, ext, exe);
        }

        /// <summary>The release archive base name, e.g. <c>banbo_darwin_arm64</c>.</summary>
        public static string ArchiveBaseName(Target target) => $"{Repo}_{target.Os}_{target.Arch}";

        /// <summary>Full download URL for the release archive.</summary>
        public static string ArchiveUrl(Target target)
            => $"https://github.com/{Owner}/{Repo}/releases/download/v{Version}/{ArchiveBaseName(target)}.{target.Ext}";

        private static async Task DownloadAndExtractAsync(Target target, string binaryPath, CancellationToken ct)
        {
            var cacheDir = CacheDir();
            Directory.CreateDirectory(cacheDir);

            var url = ArchiveUrl(target);
            byte[] archiveBytes;
            try
            {
                using (var response = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
                           .ConfigureAwait(false))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        throw new BanboException(
                            $"Failed to download banbo from {url}: HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");
                    }
#if NET5_0_OR_GREATER
                    archiveBytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
#else
                    archiveBytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
#endif
                }
            }
            catch (BanboException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new BanboException($"Failed to download banbo from {url}: {ex.Message}", ex);
            }

            // Extract atomically into a temp dir, then move the executable into place so a
            // partially written binary is never observed by a concurrent resolver.
            var tempExtract = Path.Combine(cacheDir, ".extract-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempExtract);
            try
            {
                string extractedExe;
                if (target.Ext == "zip")
                {
                    extractedExe = ExtractZip(archiveBytes, tempExtract, target.Exe);
                }
                else
                {
                    extractedExe = ExtractTarGz(archiveBytes, tempExtract, target.Exe);
                }

                lock (CacheLock)
                {
                    if (!File.Exists(binaryPath))
                    {
                        // File.Move can't overwrite on netstandard2.0; copy is simplest and safe here.
                        File.Copy(extractedExe, binaryPath, overwrite: true);
                        ChmodExecutable(binaryPath, target);
                    }
                }
            }
            finally
            {
                TryDeleteDirectory(tempExtract);
            }
        }

        private static string ExtractZip(byte[] archiveBytes, string destDir, string exeName)
        {
            using (var ms = new MemoryStream(archiveBytes))
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Read))
            {
                foreach (var entry in zip.Entries)
                {
                    var name = Path.GetFileName(entry.FullName);
                    if (string.Equals(name, exeName, StringComparison.OrdinalIgnoreCase))
                    {
                        var dest = Path.Combine(destDir, exeName);
                        entry.ExtractToFile(dest, overwrite: true);
                        return dest;
                    }
                }
            }
            throw new BanboException($"Archive did not contain the expected entry \"{exeName}\".");
        }

        private static string ExtractTarGz(byte[] archiveBytes, string destDir, string exeName)
        {
            // Prefer the in-box tar reader on net7+; fall back to a tiny tar reader on
            // netstandard2.0, and finally to the system `tar` on unix.
#if NET7_0_OR_GREATER
            using (var ms = new MemoryStream(archiveBytes))
            using (var gz = new GZipStream(ms, CompressionMode.Decompress))
            using (var tar = new System.Formats.Tar.TarReader(gz))
            {
                System.Formats.Tar.TarEntry? entry;
                while ((entry = tar.GetNextEntry()) != null)
                {
                    var name = Path.GetFileName(entry.Name);
                    if (string.Equals(name, exeName, StringComparison.OrdinalIgnoreCase) && entry.DataStream != null)
                    {
                        var dest = Path.Combine(destDir, exeName);
                        using (var fs = File.Create(dest))
                        {
                            entry.DataStream.CopyTo(fs);
                        }
                        return dest;
                    }
                }
            }
            throw new BanboException($"Archive did not contain the expected entry \"{exeName}\".");
#else
            try
            {
                return ExtractTarGzManaged(archiveBytes, destDir, exeName);
            }
            catch (BanboException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Last-ditch fallback: shell out to the system tar on unix.
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var viaTar = ExtractTarGzViaSystemTar(archiveBytes, destDir, exeName);
                    if (viaTar != null) return viaTar;
                }
                throw new BanboException($"Failed to extract tar.gz archive: {ex.Message}", ex);
            }
#endif
        }

#if !NET7_0_OR_GREATER
        // Minimal gzip + USTAR tar reader, enough for banbo's single-file archives.
        private static string ExtractTarGzManaged(byte[] archiveBytes, string destDir, string exeName)
        {
            byte[] tarBytes;
            using (var ms = new MemoryStream(archiveBytes))
            using (var gz = new GZipStream(ms, CompressionMode.Decompress))
            using (var outMs = new MemoryStream())
            {
                gz.CopyTo(outMs);
                tarBytes = outMs.ToArray();
            }

            const int blockSize = 512;
            int offset = 0;
            while (offset + blockSize <= tarBytes.Length)
            {
                // A header that is entirely zero marks the end of the archive.
                if (IsZeroBlock(tarBytes, offset))
                {
                    break;
                }

                var name = ReadTarString(tarBytes, offset, 100);
                // Honor the USTAR prefix field (offset 345, length 155) for long names.
                var prefix = ReadTarString(tarBytes, offset + 345, 155);
                if (prefix.Length > 0)
                {
                    name = prefix + "/" + name;
                }

                var sizeStr = ReadTarString(tarBytes, offset + 124, 12).Trim();
                long size = ParseOctal(sizeStr);
                byte typeFlag = tarBytes[offset + 156];

                offset += blockSize;

                bool isRegularFile = typeFlag == 0 || typeFlag == (byte)'0';
                if (isRegularFile && string.Equals(Path.GetFileName(name), exeName, StringComparison.OrdinalIgnoreCase))
                {
                    var dest = Path.Combine(destDir, exeName);
                    using (var fs = File.Create(dest))
                    {
                        fs.Write(tarBytes, offset, (int)size);
                    }
                    return dest;
                }

                // Advance past the file data, rounded up to the next 512-byte block.
                long dataBlocks = (size + blockSize - 1) / blockSize;
                offset += (int)(dataBlocks * blockSize);
            }

            throw new BanboException($"Archive did not contain the expected entry \"{exeName}\".");
        }

        private static bool IsZeroBlock(byte[] buf, int offset)
        {
            for (int i = 0; i < 512 && offset + i < buf.Length; i++)
            {
                if (buf[offset + i] != 0) return false;
            }
            return true;
        }

        private static string ReadTarString(byte[] buf, int offset, int length)
        {
            int end = offset;
            int max = offset + length;
            while (end < max && end < buf.Length && buf[end] != 0)
            {
                end++;
            }
            return Encoding.ASCII.GetString(buf, offset, end - offset);
        }

        private static long ParseOctal(string s)
        {
            long value = 0;
            foreach (var c in s)
            {
                if (c < '0' || c > '7') continue;
                value = (value << 3) + (c - '0');
            }
            return value;
        }

        private static string? ExtractTarGzViaSystemTar(byte[] archiveBytes, string destDir, string exeName)
        {
            var tmpArchive = Path.Combine(destDir, "banbo-archive.tar.gz");
            File.WriteAllBytes(tmpArchive, archiveBytes);
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "tar",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    WorkingDirectory = destDir,
                };
                psi.ArgumentList.Add("-xzf");
                psi.ArgumentList.Add(tmpArchive);

                using (var proc = Process.Start(psi))
                {
                    if (proc == null) return null;
                    proc.WaitForExit();
                    if (proc.ExitCode != 0) return null;
                }

                var candidate = Path.Combine(destDir, exeName);
                return File.Exists(candidate) ? candidate : null;
            }
            finally
            {
                try { File.Delete(tmpArchive); } catch { /* best effort */ }
            }
        }
#endif

        private static void ChmodExecutable(string path, Target target)
        {
            if (target.Os == "windows")
            {
                return;
            }

#if NET7_0_OR_GREATER
            try
            {
                var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                           UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                           UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
                File.SetUnixFileMode(path, mode);
                return;
            }
            catch
            {
                // Fall through to the chmod shell-out below.
            }
#endif
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "chmod",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                };
                psi.ArgumentList.Add("+x");
                psi.ArgumentList.Add(path);
                using (var proc = Process.Start(psi))
                {
                    proc?.WaitForExit();
                }
            }
            catch
            {
                // Non-fatal: if chmod is unavailable the exec will surface a clearer error.
            }
        }

        private static void TryDeleteDirectory(string dir)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    Directory.Delete(dir, recursive: true);
                }
            }
            catch
            {
                // Best effort cleanup.
            }
        }

        /// <summary>
        /// Executes the banbo binary with the given arguments, capturing stdout and stderr.
        /// </summary>
        /// <remarks>Exit codes 0, 1 and 2 are returned as-is; they are not errors.</remarks>
        public static BanboResult Exec(IEnumerable<string> args)
            => ExecAsync(args, CancellationToken.None).GetAwaiter().GetResult();

        /// <summary>
        /// Asynchronously executes the banbo binary with the given arguments, capturing
        /// stdout and stderr.
        /// </summary>
        public static async Task<BanboResult> ExecAsync(IEnumerable<string> args, CancellationToken cancellationToken = default)
        {
            var binary = await ResolveAsync(cancellationToken).ConfigureAwait(false);

            var psi = new ProcessStartInfo
            {
                FileName = binary,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (var arg in args)
            {
                psi.ArgumentList.Add(arg);
            }

            using (var process = new Process { StartInfo = psi })
            {
                var stdout = new StringBuilder();
                var stderr = new StringBuilder();

                try
                {
                    if (!process.Start())
                    {
                        throw new BanboException($"Failed to start banbo process at \"{binary}\".");
                    }
                }
                catch (BanboException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    throw new BanboException($"Failed to start banbo process at \"{binary}\": {ex.Message}", ex);
                }

                var stdoutTask = DrainAsync(process.StandardOutput, stdout);
                var stderrTask = DrainAsync(process.StandardError, stderr);

#if NET5_0_OR_GREATER
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
#else
                await Task.Run(() => process.WaitForExit(), cancellationToken).ConfigureAwait(false);
#endif
                await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);

                return new BanboResult(process.ExitCode, stdout.ToString(), stderr.ToString());
            }
        }

        private static async Task DrainAsync(StreamReader reader, StringBuilder sink)
        {
            var buffer = new char[4096];
            int read;
            while ((read = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            {
                sink.Append(buffer, 0, read);
            }
        }

        /// <summary>The resolved release tokens for a host.</summary>
        public sealed class Target
        {
            public Target(string os, string arch, string ext, string exe)
            {
                Os = os;
                Arch = arch;
                Ext = ext;
                Exe = exe;
            }

            /// <summary>Release OS token: <c>linux</c>, <c>darwin</c> or <c>windows</c>.</summary>
            public string Os { get; }

            /// <summary>Release arch token: <c>amd64</c> or <c>arm64</c>.</summary>
            public string Arch { get; }

            /// <summary>Archive extension: <c>tar.gz</c> or <c>zip</c>.</summary>
            public string Ext { get; }

            /// <summary>Executable name inside the archive: <c>banbo</c> or <c>banbo.exe</c>.</summary>
            public string Exe { get; }
        }
    }
}
