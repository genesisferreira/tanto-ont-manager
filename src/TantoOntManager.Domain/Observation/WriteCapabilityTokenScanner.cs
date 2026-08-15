using System.Text.RegularExpressions;

namespace TantoOntManager.Domain.Observation;

public static class WriteCapabilityTokenScanner
{
    public static readonly IReadOnlyList<string> PublicEnumerations =
    [
        "DHCP", "Static", "Bridge", "PPPoE", "IPoE", "IPOE", "Disable", "Enable",
        "On", "Off", "IPv4", "IPv6", "INTERNET", "TR069", "VoIP", "IPTV"
    ];

    public static bool IsPublicEnumeration(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (PublicEnumerations.Any(item => trimmed.Equals(item, StringComparison.OrdinalIgnoreCase))
            || Regex.IsMatch(trimmed, "^(DHCP|Static|Bridge|PPPoE|IPoE)$", RegexOptions.IgnoreCase))
        {
            return true;
        }

        return false;
    }

    public static bool LooksLikePppoe(string? value)
        => !string.IsNullOrWhiteSpace(value)
           && Regex.IsMatch(value, "(?i)\\bpppoe\\b");

    public static bool LooksLikeCreate(string? value)
        => !string.IsNullOrWhiteSpace(value)
           && Regex.IsMatch(value, "(?i)(create\\s*new\\s*item|\\badd\\b|new\\s*wan|\\b\\+\\b)");

    public static bool LooksLikeApplySave(string? value)
        => !string.IsNullOrWhiteSpace(value)
           && Regex.IsMatch(value, "(?i)\\b(apply|save)\\b");

    public static WriteCapabilityTokenScan Scan(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return WriteCapabilityTokenScan.Empty;
        }

        var ipType = new List<string>();
        var type = new List<string>();
        var foundPppoe = LooksLikePppoe(text);
        var foundCreate = LooksLikeCreate(text);
        var foundApply = LooksLikeApplySave(text);
        foreach (var token in PublicEnumerations)
        {
            if (Regex.IsMatch(text, $@"\b{Regex.Escape(token)}\b", RegexOptions.IgnoreCase))
            {
                if (token is "DHCP" or "Static")
                {
                    AddUnique(ipType, token);
                }

                AddUnique(type, token);
            }
        }

        return new WriteCapabilityTokenScan(ipType, type, foundPppoe, foundCreate, foundApply);
    }

    private static void AddUnique(List<string> list, string value)
    {
        if (!list.Exists(item => item.Equals(value, StringComparison.OrdinalIgnoreCase)))
        {
            list.Add(value);
        }
    }
}

public sealed record WriteCapabilityTokenScan(
    IReadOnlyList<string> IpTypeHints,
    IReadOnlyList<string> TypeHints,
    bool MentionsPppoe,
    bool MentionsCreate,
    bool MentionsApplySave)
{
    public static WriteCapabilityTokenScan Empty { get; } = new([], [], false, false, false);
}
