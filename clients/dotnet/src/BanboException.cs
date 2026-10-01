using System;

namespace Banbo
{
    /// <summary>
    /// Thrown when the banbo binary cannot be resolved or executed, or when its
    /// output cannot be parsed.
    /// </summary>
    /// <remarks>
    /// Findings-driven non-zero exit codes (1 and 2) are <em>not</em> errors: they
    /// mean banbo ran successfully and found issues. Only exit codes other than
    /// 0, 1 or 2 raise this exception.
    /// </remarks>
    public class BanboException : Exception
    {
        public BanboException(string message)
            : base(message)
        {
        }

        public BanboException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
