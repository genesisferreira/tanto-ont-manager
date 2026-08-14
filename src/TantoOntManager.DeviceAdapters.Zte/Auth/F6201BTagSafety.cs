using System.Text.RegularExpressions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BTagSafety
{
    private static readonly HashSet<string> DestructiveTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "apply", "save", "submit", "create", "delete", "remove", "reset", "reboot",
        "upgrade", "upload", "restore", "factory", "firmware", "password", "account",
        "write", "set", "modify", "download", "backup", "wizard", "logout", "logoff",
        "chgpwd"
    };

    private static readonly HashSet<string> DubiousTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "settings", "config", "configure", "editor"
    };

    private static readonly HashSet<string> LongUnambiguous = new(StringComparer.OrdinalIgnoreCase)
    {
        "reboot", "firmware", "password", "factory", "upgrade", "logout", "logoff", "chgpwd"
    };

    public static bool IsBlocked(string? tag)
        => Classify(tag).Blocked;

    public static (bool Blocked, string Reason) Classify(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag))
        {
            return (true, "Tag vazia; permanece bloqueada.");
        }

        var tokens = Tokenize(tag).ToList();
        foreach (var token in tokens)
        {
            if (DestructiveTokens.Contains(token))
            {
                return (true, $"Token de ação '{token}' na tag; GET bloqueado.");
            }

            if (DubiousTokens.Contains(token))
            {
                return (true, $"Token duvidoso '{token}'; permanece bloqueado.");
            }
        }

        foreach (var token in tokens)
        {
            foreach (var word in LongUnambiguous)
            {
                if (token.Contains(word, StringComparison.OrdinalIgnoreCase) && token.Length != word.Length)
                {
                    return (true, $"Identificador contém ação '{word}'; permanece bloqueado.");
                }
            }
        }

        return (false, "Tag sem token de ação.");
    }

    public static IReadOnlyList<string> Tokenize(string tag)
    {
        var tokens = new List<string>();
        foreach (var part in tag.Split(['_', '-'], StringSplitOptions.RemoveEmptyEntries))
        {
            var pieces = Regex.Split(part, "(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])");
            foreach (var piece in pieces)
            {
                if (!string.IsNullOrWhiteSpace(piece))
                {
                    tokens.Add(piece);
                }
            }
        }

        return tokens;
    }
}
