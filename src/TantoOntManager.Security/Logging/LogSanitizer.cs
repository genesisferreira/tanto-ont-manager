using System.Security.Cryptography;
using TantoOntManager.Domain.Audit;

namespace TantoOntManager.Security.Logging;

public sealed class LogSanitizer
{
    public string Sanitize(string? message) => SensitiveDataMasker.SanitizeLogText(message);

    public string Fingerprint(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "[empty]";
        }

        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash)[..8];
    }
}
