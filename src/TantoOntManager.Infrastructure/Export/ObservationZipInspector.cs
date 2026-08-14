using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.Infrastructure.Export;

public static class ObservationZipInspector
{
    private static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase)
    {
        "observation-summary.txt",
        "observed-get-contracts.json",
        "response-structures.json",
        "blocked-requests.json",
        "manifest.json"
    };

    public static ObservationZipInspection Inspect(string zipPath)
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
        var cookies = Regex.IsMatch(text, "(?i)(set-cookie|SID_HTTPS_=)");
        var credentials = Regex.IsMatch(text, "(?i)(password|senha)\\s*[:=]\\s*\\S+");
        var tokens = Regex.IsMatch(text, "(?i)_sessionTOKEN=|challenge\\s*[:=]\\s*\\S+");
        var raw = Regex.IsMatch(text, "(?i)<html|</html>")
                  || names.Any(name => name.EndsWith(".html", StringComparison.OrdinalIgnoreCase));
        var masked = names.All(name => Allowed.Contains(name)) && !cookies && !credentials && !tokens && !raw;
        return new ObservationZipInspection(cookies, credentials, tokens, raw, masked, 0, names);
    }
}
