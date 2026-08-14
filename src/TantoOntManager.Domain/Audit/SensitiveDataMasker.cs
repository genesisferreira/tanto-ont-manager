using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace TantoOntManager.Domain.Audit;

public static class SensitiveDataMasker
{
    private static readonly Regex AuthorizationHeader = new(
        "(?i)(authorization\\s*[:=]\\s*)([^\\s,;]+)",
        RegexOptions.Compiled);

    private static readonly Regex CookieHeader = new(
        "(?i)(cookie\\s*[:=]\\s*)(.+)",
        RegexOptions.Compiled);

    private static readonly Regex PasswordAssignment = new(
        "(?i)(pass(word)?|senha|pwd|token|secret)\\s*([:=])\\s*([^\\s,;\"']+)",
        RegexOptions.Compiled);

    public static string MaskSerial(string? serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return "—";
        }

        var value = serial.Trim();
        if (value.Length <= 6)
        {
            return value[0] + new string('*', Math.Max(1, value.Length - 2)) + value[^1];
        }

        return value[..3] + new string('*', value.Length - 6) + value[^3..];
    }

    public static string MaskMac(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac))
        {
            return "—";
        }

        var hex = Regex.Replace(mac, "[^A-Fa-f0-9]", string.Empty).ToUpperInvariant();
        if (hex.Length < 12)
        {
            return MaskSerial(mac);
        }

        return $"{hex[..2]}:**:**:**:**:{hex[^2..]}";
    }

    public static string MaskUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return "—";
        }

        var value = username.Trim();
        if (value.Length <= 2)
        {
            return new string('*', value.Length);
        }

        return value[0] + new string('*', value.Length - 2) + value[^1];
    }

    public static string RedactSecret() => "[redacted]";

    public static PhysicalAddress? TryParseMac(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac))
        {
            return null;
        }

        var hex = Regex.Replace(mac, "[^A-Fa-f0-9]", string.Empty);
        if (hex.Length != 12)
        {
            return null;
        }

        return PhysicalAddress.Parse(hex);
    }

    public static string SanitizeLogText(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var sanitized = AuthorizationHeader.Replace(text, "$1[redacted]");
        sanitized = CookieHeader.Replace(sanitized, "$1[redacted]");
        sanitized = PasswordAssignment.Replace(sanitized, "$1$3 [redacted]");
        return sanitized;
    }
}
