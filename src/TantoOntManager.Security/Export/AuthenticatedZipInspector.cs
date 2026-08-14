using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using TantoOntManager.Domain.Export;

namespace TantoOntManager.Security.Export;

public static class AuthenticatedZipInspector
{
    private static readonly Regex Cookie = new("(?i)(set-cookie|SID_HTTPS_)", RegexOptions.Compiled);
    private static readonly Regex RawHtml = new("(?i)<html|</html>|<script", RegexOptions.Compiled);
    private static readonly HashSet<string> AllowedEntries = new(StringComparer.OrdinalIgnoreCase)
    {
        "manifest.json",
        "device-information.json",
        "pon-status.json",
        "wan-summary.json",
        "safe-read-inventory.json",
        "authenticated-diagnostic-summary.txt"
    };

    public static AuthenticatedZipInspection Inspect(string zipPath, string? serial, string? mac)
    {
        using var zip = ZipFile.OpenRead(zipPath);
        var names = zip.Entries.Select(entry => entry.Name).ToList();
        var combined = new StringBuilder();
        foreach (var entry in zip.Entries)
        {
            using var stream = entry.Open();
            using var reader = new StreamReader(stream, Encoding.UTF8);
            combined.AppendLine(reader.ReadToEnd());
        }

        var text = combined.ToString();
        var masked = !ContainsFullIdentifier(text, serial, mac) && names.All(name => AllowedEntries.Contains(name));
        return new AuthenticatedZipInspection(
            Cookie.IsMatch(text),
            ContainsCredentialValue(text),
            RawHtml.IsMatch(text) || names.Any(name => name.EndsWith(".html", StringComparison.OrdinalIgnoreCase)),
            masked,
            names);
    }

    private static bool ContainsCredentialValue(string text)
        => Regex.IsMatch(text, "(?i)(password|senha|frm_password|_sessionTOKEN)\\s*[:=]\\s*\"?[^\"\\s,\\]]+");

    private static bool ContainsFullIdentifier(string text, string? serial, string? mac)
    {
        if (!string.IsNullOrWhiteSpace(serial) && serial.Length >= 6 && text.Contains(serial, StringComparison.Ordinal))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(mac) && mac.Length >= 12 && text.Contains(mac, StringComparison.OrdinalIgnoreCase);
    }
}
