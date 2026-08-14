using System.Text.RegularExpressions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BPriorityMenu
{
    public const string DeviceStatus = "Management & Diagnosis → Status";
    public const string PonInformation = "Internet → PON Information";
    public const string WanUnderStatus = "Internet → Status → WAN";
    public const string Wan = "Internet → WAN";

    public static readonly IReadOnlyList<string> All =
    [
        DeviceStatus,
        PonInformation,
        WanUnderStatus,
        Wan
    ];

    public static string Normalize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        var value = text.Replace("&", " and ", StringComparison.Ordinal)
            .Replace("→", ">", StringComparison.Ordinal)
            .ToLowerInvariant();
        return Regex.Replace(value, @"\s+", " ").Trim();
    }

    public static string? Match(string? menuPath)
    {
        var parts = Split(menuPath);
        if (parts.Count == 0)
        {
            return null;
        }

        if (Matches(parts, "management and diagnosis", "status"))
        {
            return DeviceStatus;
        }

        if (Matches(parts, "internet", "pon information"))
        {
            return PonInformation;
        }

        if (Matches(parts, "internet", "status", "wan"))
        {
            return WanUnderStatus;
        }

        if (Matches(parts, "internet", "wan") || Matches(parts, "internet", "wan status"))
        {
            return Wan;
        }

        return null;
    }

    public static IReadOnlyList<string> Split(string? menuPath)
    {
        var normalized = Normalize(menuPath);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return [];
        }

        return normalized
            .Split('>', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
    }

    private static bool Matches(IReadOnlyList<string> parts, params string[] needles)
    {
        if (needles.Length == 0 || parts.Count < needles.Length)
        {
            return false;
        }

        var start = 0;
        foreach (var needle in needles)
        {
            var found = -1;
            for (var i = start; i < parts.Count; i++)
            {
                if (parts[i].Equals(needle, StringComparison.Ordinal))
                {
                    found = i;
                    break;
                }
            }

            if (found < 0)
            {
                return false;
            }

            start = found + 1;
        }

        return true;
    }
}
