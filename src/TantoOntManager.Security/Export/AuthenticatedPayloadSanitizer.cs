using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TantoOntManager.Domain.Audit;

namespace TantoOntManager.Security.Export;

public static class AuthenticatedPayloadSanitizer
{
    private static readonly Regex Mac = new(
        @"(?i)\b([0-9A-F]{2}([:-])){5}[0-9A-F]{2}\b",
        RegexOptions.Compiled);

    private static readonly Regex Serialish = new(
        @"(?i)\b(serial(number)?|sn|gponsn)\s*([:=])\s*([A-Z0-9\-]{6,})",
        RegexOptions.Compiled);

    private static readonly Regex Ssid = new(
        @"(?i)\b(ssid|wlan\s*name)\s*([:=])\s*([^\s,;""']+)",
        RegexOptions.Compiled);

    private static readonly Regex PppoeUser = new(
        @"(?i)\b(pppoe\s*(user(name)?|account)|username)\s*([:=])\s*([^\s,;""']+)",
        RegexOptions.Compiled);

    private static readonly Regex PublicIpv4 = new(
        @"\b(\d{1,3}\.){3}\d{1,3}\b",
        RegexOptions.Compiled);

    private static readonly Regex Tokenish = new(
        @"(?i)\b(sess_token|_sessionTOKEN|csrf|nonce|challenge|SID_HTTPS_)\s*([:=])\s*([^\s,;""']+)",
        RegexOptions.Compiled);

    public static string Sanitize(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var sanitized = SensitiveDataMasker.SanitizeLogText(text);
        sanitized = Mac.Replace(sanitized, match => SensitiveDataMasker.MaskMac(match.Value));
        sanitized = Serialish.Replace(sanitized, "$1$3 [redacted]");
        sanitized = Ssid.Replace(sanitized, "$1$2 [redacted]");
        sanitized = PppoeUser.Replace(sanitized, "$1$4 [redacted]");
        sanitized = Tokenish.Replace(sanitized, "$1$2 [redacted]");
        sanitized = PublicIpv4.Replace(sanitized, match => MaskPublicIp(match.Value));
        return sanitized;
    }

    public static string Sha256Short(string? text)
    {
        var sanitized = Sanitize(text);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sanitized))).ToLowerInvariant();
        return hash[..Math.Min(8, hash.Length)];
    }

    public static bool LooksUnsanitized(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        if (Regex.IsMatch(text, "(?i)(set-cookie|authorization\\s*:)"))
        {
            return true;
        }

        if (Regex.IsMatch(text, "(?i)(password|senha)\\s*[:=]\\s*\\S+"))
        {
            return true;
        }

        return false;
    }

    private static string MaskPublicIp(string value)
    {
        if (!IPAddress.TryParse(value, out var address))
        {
            return value;
        }

        var bytes = address.GetAddressBytes();
        if (bytes.Length != 4)
        {
            return value;
        }

        if (bytes[0] == 10
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || bytes[0] == 127)
        {
            return value;
        }

        return $"{bytes[0]}.{bytes[1]}.x.x";
    }
}
