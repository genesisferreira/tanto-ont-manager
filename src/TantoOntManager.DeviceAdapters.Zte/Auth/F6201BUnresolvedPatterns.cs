using System.Text.RegularExpressions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BUnresolvedPatterns
{
    private static readonly (string Pattern, string Label)[] Rules =
    [
        (@"_type=menuData&_tag=\s*[""']?\s*\+", "menuData+_tag concatenado com variável; tag não inventada"),
        (@"_type=menuView&_tag=\s*[""']?\s*\+", "menuView+_tag concatenado com variável; tags só das evidências literais/menu"),
        (@"_type=hiddenData&_tag=\s*[""']?\s*\+", "hiddenData+_tag concatenado com variável; tag não inventada")
    ];

    public static IReadOnlyList<string> Find(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return [];
        }

        var found = new List<string>();
        foreach (var rule in Rules)
        {
            if (Regex.IsMatch(body, rule.Pattern, RegexOptions.IgnoreCase)
                && !found.Contains(rule.Label, StringComparer.Ordinal))
            {
                found.Add(rule.Label);
            }
        }

        return found;
    }
}
