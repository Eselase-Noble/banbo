using System.Threading;
using System.Threading.Tasks;

namespace Banbo
{
    /// <summary>
    /// Entry point for programmatic access to the banbo security scanner.
    /// </summary>
    /// <remarks>
    /// The underlying banbo CLI binary is resolved lazily on first use: if
    /// <c>BANBO_BINARY</c> is set it is used directly, otherwise the matching release
    /// binary is downloaded once and cached per user.
    /// <example>
    /// <code>
    /// var result = BanboClient.Scan("example.com").Authorized().NoAi().Run();
    /// foreach (var f in result.Findings)
    ///     System.Console.WriteLine($"[{f.Severity}] {f.Title}");
    /// </code>
    /// </example>
    /// </remarks>
    public static class BanboClient
    {
        /// <summary>
        /// Begins a network/application <c>scan</c> of <paramref name="target"/>.
        /// </summary>
        /// <param name="target">Host, URL or IP to scan.</param>
        /// <returns>A fluent <see cref="BanboCommand"/> builder.</returns>
        public static BanboCommand Scan(string target) => BanboCommand.Scan(target);

        /// <summary>
        /// Begins a source-code (<c>code</c>) review of <paramref name="path"/>.
        /// </summary>
        /// <param name="path">Directory or file to review (defaults to the current directory).</param>
        /// <returns>A fluent <see cref="BanboCommand"/> builder.</returns>
        public static BanboCommand Code(string path = ".") => BanboCommand.Code(path);

        /// <summary>
        /// Runs the banbo binary with arbitrary arguments, capturing stdout and stderr.
        /// </summary>
        /// <remarks>Exit codes 0, 1 and 2 are returned as-is and are not treated as errors.</remarks>
        /// <param name="args">Raw arguments to pass to banbo (e.g. <c>"version"</c>).</param>
        public static BanboResult Exec(params string[] args) => BinaryResolver.Exec(args);

        /// <summary>
        /// Asynchronously runs the banbo binary with arbitrary arguments.
        /// </summary>
        public static Task<BanboResult> ExecAsync(string[] args, CancellationToken cancellationToken = default)
            => BinaryResolver.ExecAsync(args, cancellationToken);

        /// <summary>Returns the banbo binary version string (runs <c>banbo version</c>).</summary>
        public static string Version()
        {
            var result = BinaryResolver.Exec(new[] { "version" });
            if (!result.RanOk)
            {
                throw new BanboException($"banbo version exited with code {result.ExitCode}: {result.StdErr?.Trim()}");
            }
            return result.StdOut.Trim();
        }
    }
}
