using System.Text.RegularExpressions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BProvenQueryParameter
{
    private static readonly HashSet<string> ForbiddenNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "passwd", "token", "cookie", "sess", "session", "challenge",
        "serial", "username", "user", "sid", "action", "submit", "apply", "save"
    };

    private static readonly HashSet<string> ForbiddenValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "apply", "save", "submit", "login", "logoff", "logout", "delete", "reboot"
    };

    public static bool TryCreate(string? name, string? value, out string normalizedName, out string normalizedValue)
    {
        normalizedName = string.Empty;
        normalizedValue = string.Empty;
        if (IsCacheBuster(name, value))
        {
            normalizedName = "_";
            normalizedValue = value!;
            return true;
        }

        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (!Regex.IsMatch(name, "^[A-Za-z][A-Za-z0-9_]*$")
            || !Regex.IsMatch(value, "^[A-Za-z0-9_\\-]+$"))
        {
            return false;
        }

        if (ForbiddenNames.Contains(name)
            || name.Contains("token", StringComparison.OrdinalIgnoreCase)
            || name.Contains("cookie", StringComparison.OrdinalIgnoreCase)
            || name.Contains("pass", StringComparison.OrdinalIgnoreCase)
            || name.Contains("serial", StringComparison.OrdinalIgnoreCase)
            || ForbiddenValues.Contains(value))
        {
            return false;
        }

        normalizedName = name;
        normalizedValue = value;
        return true;
    }

    public static bool IsCacheBuster(string? name, string? value)
        => name == "_"
           && !string.IsNullOrEmpty(value)
           && value.All(char.IsDigit);

    public static bool IsSafe(string? name, string? value)
        => TryCreate(name, value, out _, out _);

    public static string Format(IReadOnlyDictionary<string, string>? extras)
    {
        if (extras is null || extras.Count == 0)
        {
            return string.Empty;
        }

        return string.Join('&', extras
            .Where(pair => IsSafe(pair.Key, pair.Value))
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => $"{pair.Key}={pair.Value}"));
    }

    public static IReadOnlyDictionary<string, string> Merge(
        IReadOnlyDictionary<string, string>? left,
        IReadOnlyDictionary<string, string>? right)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in new[] { left, right })
        {
            if (source is null)
            {
                continue;
            }

            foreach (var pair in source)
            {
                if (TryCreate(pair.Key, pair.Value, out var name, out var value))
                {
                    result[name] = value;
                }
            }
        }

        return result.Count == 0
            ? new Dictionary<string, string>()
            : result;
    }
}
