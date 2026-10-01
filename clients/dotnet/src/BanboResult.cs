namespace Banbo
{
    /// <summary>
    /// The raw result of executing the banbo binary: its exit code and captured streams.
    /// </summary>
    public sealed class BanboResult
    {
        public BanboResult(int exitCode, string stdOut, string stdErr)
        {
            ExitCode = exitCode;
            StdOut = stdOut;
            StdErr = stdErr;
        }

        /// <summary>
        /// The process exit code. 0 (clean/info), 1 (low/medium) and 2 (high/critical)
        /// all mean banbo ran successfully. Any other code indicates an execution error.
        /// </summary>
        public int ExitCode { get; }

        /// <summary>Everything banbo wrote to standard output.</summary>
        public string StdOut { get; }

        /// <summary>Everything banbo wrote to standard error.</summary>
        public string StdErr { get; }

        /// <summary>
        /// True when the exit code is one banbo uses to signal a successful run
        /// (0, 1 or 2). Non-success codes indicate an error worth throwing on.
        /// </summary>
        public bool RanOk => ExitCode == 0 || ExitCode == 1 || ExitCode == 2;

        public override string ToString()
            => $"BanboResult{{exitCode={ExitCode}, stdoutBytes={StdOut?.Length ?? 0}, stderrBytes={StdErr?.Length ?? 0}}}";
    }
}
