using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Text.Json;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record LoginBootstrap(bool TokenPresent, bool ErrorMessagePresent, bool PromptPresent, int LockingTime);

public sealed record LoginPostOutcome(
    bool RefreshRequested,
    bool ErrorMessagePresent,
    bool PromptPresent,
    bool LooksExpired,
    int LockingTime);

public static class F6201BV9310P8N1LoginParser
{
    public static string HashPassword(string password, string challenge)
    {
        var bytes = Encoding.UTF8.GetBytes(password + challenge);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    public static string? ReadChallenge(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            return null;
        }

        try
        {
            var document = XDocument.Parse(xml, LoadOptions.PreserveWhitespace);
            var root = document.Root;
            if (root is null
                || !root.Name.LocalName.Equals(F6201BV9310P8N1AuthContract.XmlChallengeRoot, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var text = root.Value;
            return string.IsNullOrWhiteSpace(text) ? null : text;
        }
        catch (System.Xml.XmlException)
        {
            return null;
        }
    }

    public static LoginBootstrap ParseBootstrap(string json)
    {
        if (!TryParseObject(json, out var root))
        {
            return new LoginBootstrap(false, false, false, 0);
        }

        return new LoginBootstrap(
            HasNonEmpty(root, "sess_token"),
            HasNonEmpty(root, "loginErrMsg"),
            HasNonEmpty(root, "promptMsg"),
            ReadInt(root, "lockingTime"));
    }

    public static LoginPostOutcome ParsePost(string json)
    {
        if (!TryParseObject(json, out var root))
        {
            return new LoginPostOutcome(false, false, false, false, 0);
        }

        var err = ReadString(root, "loginErrMsg") + " " + ReadString(root, "promptMsg") + " " + ReadString(root, "IF_ERRORSTR");
        var expired = err.Contains("expir", StringComparison.OrdinalIgnoreCase)
                      || err.Contains("timeout", StringComparison.OrdinalIgnoreCase)
                      || err.Contains("refresh", StringComparison.OrdinalIgnoreCase) && err.Contains("try again", StringComparison.OrdinalIgnoreCase);

        return new LoginPostOutcome(
            ReadBool(root, "login_need_refresh"),
            HasNonEmpty(root, "loginErrMsg"),
            HasNonEmpty(root, "promptMsg"),
            expired,
            ReadInt(root, "lockingTime"));
    }

    private static bool TryParseObject(string json, out JsonElement root)
    {
        root = default;
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            root = document.RootElement.Clone();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool HasNonEmpty(JsonElement root, string name)
        => root.TryGetProperty(name, out var value)
           && value.ValueKind == JsonValueKind.String
           && !string.IsNullOrWhiteSpace(value.GetString());

    private static bool ReadBool(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            return false;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Number => value.TryGetInt32(out var number) && number != 0,
            JsonValueKind.String => value.GetString() is "1" or "true" or "True" or "yes",
            _ => false
        };
    }

    private static int ReadInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            return 0;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
        {
            return number;
        }

        return int.TryParse(value.GetString(), out var parsed) ? parsed : 0;
    }

    private static string ReadString(JsonElement root, string name)
        => root.TryGetProperty(name, out var value) ? value.ToString() : string.Empty;
}
