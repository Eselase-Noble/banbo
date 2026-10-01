using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;

namespace Banbo
{
    /// <summary>
    /// A fluent builder for a single banbo invocation (<c>scan</c> or <c>code</c>).
    /// </summary>
    /// <remarks>
    /// Build up flags with the chainable methods, then call <see cref="Run"/> /
    /// <see cref="RunAsync"/> for a parsed <see cref="ScanResult"/>, or
    /// <see cref="RunRaw"/> / <see cref="RunRawAsync"/> for the raw process result.
    /// Instances are not thread-safe; construct one per invocation.
    /// </remarks>
    public sealed class BanboCommand
    {
        private readonly string _subcommand; // "scan" or "code"
        private readonly string _targetOrPath;

        private bool _authorized;
        private bool _full;
        private bool _noAi;
        private bool _active;
        private bool _noColor;
        private string? _ports;
        private string? _timeout;

        private BanboCommand(string subcommand, string targetOrPath)
        {
            _subcommand = subcommand;
            _targetOrPath = targetOrPath;
        }

        internal static BanboCommand Scan(string target)
        {
            if (string.IsNullOrWhiteSpace(target))
            {
                throw new ArgumentException("A scan target is required.", nameof(target));
            }
            return new BanboCommand("scan", target);
        }

        internal static BanboCommand Code(string path)
        {
            return new BanboCommand("code", string.IsNullOrWhiteSpace(path) ? "." : path);
        }

        /// <summary>
        /// Confirms you are authorized to scan the target (passes <c>-y</c>). Required for
        /// most active <c>scan</c> operations.
        /// </summary>
        public BanboCommand Authorized()
        {
            _authorized = true;
            return this;
        }

        /// <summary>Requests a full <c>code</c> review (passes <c>--full</c>).</summary>
        public BanboCommand Full()
        {
            _full = true;
            return this;
        }

        /// <summary>Disables the AI enrichment step (passes <c>--no-ai</c>).</summary>
        public BanboCommand NoAi()
        {
            _noAi = true;
            return this;
        }

        /// <summary>Enables active probing for a <c>scan</c> (passes <c>--active</c>).</summary>
        public BanboCommand Active()
        {
            _active = true;
            return this;
        }

        /// <summary>Disables ANSI color in banbo output (passes <c>--no-color</c>).</summary>
        public BanboCommand NoColor()
        {
            _noColor = true;
            return this;
        }

        /// <summary>Restricts a <c>scan</c> to the given ports (passes <c>--ports</c>).</summary>
        /// <param name="ports">Port numbers to scan.</param>
        public BanboCommand Ports(params int[] ports)
        {
            if (ports == null || ports.Length == 0)
            {
                _ports = null;
                return this;
            }
            var parts = new string[ports.Length];
            for (int i = 0; i < ports.Length; i++)
            {
                parts[i] = ports[i].ToString(CultureInfo.InvariantCulture);
            }
            _ports = string.Join(",", parts);
            return this;
        }

        /// <summary>Restricts a <c>scan</c> to the given ports (passes <c>--ports</c>).</summary>
        /// <param name="ports">A comma-separated port list, e.g. <c>"80,443"</c>.</param>
        public BanboCommand Ports(string ports)
        {
            _ports = string.IsNullOrWhiteSpace(ports) ? null : ports;
            return this;
        }

        /// <summary>Sets the per-operation timeout (passes <c>--timeout</c>).</summary>
        /// <param name="timeout">A Go duration string, e.g. <c>"5s"</c>.</param>
        public BanboCommand Timeout(string timeout)
        {
            _timeout = string.IsNullOrWhiteSpace(timeout) ? null : timeout;
            return this;
        }

        /// <summary>Sets the per-operation timeout (passes <c>--timeout</c>).</summary>
        /// <param name="timeout">A duration; rendered as whole seconds (e.g. <c>5s</c>).</param>
        public BanboCommand Timeout(TimeSpan timeout)
        {
            _timeout = ((long)timeout.TotalSeconds).ToString(CultureInfo.InvariantCulture) + "s";
            return this;
        }

        /// <summary>Builds the full argument vector passed to the banbo binary.</summary>
        public IReadOnlyList<string> BuildArgs()
        {
            var args = new List<string> { _subcommand, _targetOrPath, "-o", "json" };

            if (_subcommand == "scan")
            {
                if (_authorized) args.Add("--i-am-authorized");
                if (_active) args.Add("--active");
                if (!string.IsNullOrEmpty(_ports))
                {
                    args.Add("--ports");
                    args.Add(_ports!);
                }
                if (!string.IsNullOrEmpty(_timeout))
                {
                    args.Add("--timeout");
                    args.Add(_timeout!);
                }
            }
            else // code
            {
                if (_full) args.Add("--full");
            }

            if (_noAi) args.Add("--no-ai");
            if (_noColor) args.Add("--no-color");

            return args;
        }

        /// <summary>Runs banbo and returns the parsed <see cref="ScanResult"/>.</summary>
        /// <exception cref="BanboException">If banbo fails to run or its output cannot be parsed.</exception>
        public ScanResult Run()
            => RunAsync(CancellationToken.None).GetAwaiter().GetResult();

        /// <summary>Asynchronously runs banbo and returns the parsed <see cref="ScanResult"/>.</summary>
        /// <exception cref="BanboException">If banbo fails to run or its output cannot be parsed.</exception>
        public async Task<ScanResult> RunAsync(CancellationToken cancellationToken = default)
        {
            var raw = await RunRawAsync(cancellationToken).ConfigureAwait(false);
            return ScanResult.Parse(raw.StdOut);
        }

        /// <summary>Runs banbo and returns the raw process result (exit code + streams).</summary>
        /// <exception cref="BanboException">If banbo exits with a non-success code (other than 0/1/2).</exception>
        public BanboResult RunRaw()
            => RunRawAsync(CancellationToken.None).GetAwaiter().GetResult();

        /// <summary>
        /// Asynchronously runs banbo and returns the raw process result (exit code + streams).
        /// </summary>
        /// <exception cref="BanboException">If banbo exits with a non-success code (other than 0/1/2).</exception>
        public async Task<BanboResult> RunRawAsync(CancellationToken cancellationToken = default)
        {
            var result = await BinaryResolver.ExecAsync(BuildArgs(), cancellationToken).ConfigureAwait(false);
            if (!result.RanOk)
            {
                var detail = string.IsNullOrWhiteSpace(result.StdErr) ? result.StdOut : result.StdErr;
                throw new BanboException(
                    $"banbo exited with code {result.ExitCode}: {detail?.Trim()}");
            }
            return result;
        }
    }
}
