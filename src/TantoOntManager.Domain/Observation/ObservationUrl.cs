using System.Text.RegularExpressions;
using TantoOntManager.Domain.Audit;

namespace TantoOntManager.Domain.Observation;

public static class ObservationUrl
{
    private static readonly HashSet<string> SensitiveKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "_sessiontoken", "sess_token", "sessiontoken", "token", "csrf", "nonce", "challenge",
        "sid", "cookie", "authorization", "password", "pass", "pwd", "senha", "secret",
        "username", "user", "pppoe", "pppoeuser", "pppoeusername", "loid", "serial",
        "serialnumber", "mac", "macaddress", "gponsn"
    };

    public static string PathAndQuery(Uri uri)
        => string.IsNullOrEmpty(uri.Query) ? uri.AbsolutePath : uri.AbsolutePath + uri.Query;

    public static string Normalize(Uri uri) => Normalize(PathAndQuery(uri));

    public static string Normalize(string pathAndQuery)
    {
        if (string.IsNullOrWhiteSpace(pathAndQuery))
        {
            return "/";
        }

        var trimmed = pathAndQuery.Trim();
        var queryIndex = trimmed.IndexOf('?');
        if (queryIndex < 0)
        {
            return trimmed.ToLowerInvariant();
        }

        var path = trimmed[..queryIndex];
        var pairs = ParseQuery(trimmed[(queryIndex + 1)..])
            .Select(pair => new
            {
                Key = pair.Key.ToLowerInvariant(),
                Value = SensitiveKeys.Contains(pair.Key) ? "[redacted]" : pair.Value.ToLowerInvariant()
            })
            .OrderBy(part => part.Key, StringComparer.Ordinal)
            .ThenBy(part => part.Value, StringComparer.Ordinal)
            .Select(part => part.Key + "=" + part.Value);
        return path.ToLowerInvariant() + "?" + string.Join("&", pairs);
    }

    public static IReadOnlyDictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var text = query.StartsWith('?') ? query[1..] : query;
        if (string.IsNullOrWhiteSpace(text))
        {
            return result;
        }

        foreach (var part in text.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pieces = part.Split('=', 2);
            var key = Uri.UnescapeDataString(pieces[0]);
            var value = pieces.Length > 1 ? Uri.UnescapeDataString(pieces[1]) : string.Empty;
            result[key] = value;
        }

        return result;
    }

    public static string? TypeOf(Uri uri)
        => ParseQuery(uri.Query).TryGetValue("_type", out var type) ? type : null;

    public static string? TagOf(Uri uri)
        => ParseQuery(uri.Query).TryGetValue("_tag", out var tag) ? tag : null;

    public static IReadOnlyList<string> ExtraNames(Uri uri)
        => ParseQuery(uri.Query)
            .Keys
            .Where(key => !key.Equals("_type", StringComparison.OrdinalIgnoreCase)
                          && !key.Equals("_tag", StringComparison.OrdinalIgnoreCase))
            .ToList();

    public static IReadOnlyDictionary<string, string> ExtraValuesSanitized(Uri uri)
    {
        var extras = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in ParseQuery(uri.Query))
        {
            if (pair.Key.Equals("_type", StringComparison.OrdinalIgnoreCase)
                || pair.Key.Equals("_tag", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            extras[pair.Key] = SanitizeValue(pair.Key, pair.Value);
        }

        return extras;
    }

    public static string SanitizeValue(string key, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (SensitiveKeys.Contains(key) || LooksLikeSecret(key, value))
        {
            return "[redacted]";
        }

        if (Regex.IsMatch(key, "(?i)(mac|serial|loid|gponsn)"))
        {
            return SensitiveDataMasker.MaskSerial(value);
        }

        if (Regex.IsMatch(value, "(?i)^([0-9A-F]{2}[:-]){5}[0-9A-F]{2}$"))
        {
            return SensitiveDataMasker.MaskMac(value);
        }

        if (Regex.IsMatch(value, @"^\d{1,3}(\.\d{1,3}){3}$"))
        {
            return SensitiveDataMasker.MaskIpv4(value);
        }

        return value.Length > 96 ? value[..12] + "…" : value;
    }

    public static bool LooksLikeSecret(string key, string value)
        => SensitiveKeys.Contains(key)
           || Regex.IsMatch(key, "(?i)(pass|token|secret|challenge|sid|cookie|auth)")
           || Regex.IsMatch(value, "(?i)^(sid_https_|bearer\\s)");

    public static string PathSanitized(Uri uri)
        => AuthenticatedPath(Normalize(uri));

    private static string AuthenticatedPath(string normalized)
        => Regex.Replace(normalized, "(?i)(_sessiontoken|sess_token|token|challenge|sid)=([^&]*)", "$1=[redacted]");
}
