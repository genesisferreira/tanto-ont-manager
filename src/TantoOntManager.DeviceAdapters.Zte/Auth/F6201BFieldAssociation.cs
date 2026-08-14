using System.Text.RegularExpressions;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BFieldAssociation
{
    public static string Compact(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : Regex.Replace(value, "[^A-Za-z0-9]", string.Empty).ToUpperInvariant();

    public static bool NamesEqual(string? actual, string expected)
        => Compact(actual) == Compact(expected);

    public static bool MatchesAny(string? actual, params string[] expected)
        => expected.Any(candidate => NamesEqual(actual, candidate));

    public static bool IsExactSoftwareFirmwareField(string? name)
        => MatchesAny(name, "Software Version", "SoftwareVersion", "Firmware Version", "FirmwareVersion");

    public static bool IsUsableScalar(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (trimmed.Length > 96)
        {
            return false;
        }

        if (trimmed.Contains('<') || trimmed.Contains('>') || trimmed.Contains('{') || trimmed.Contains('}'))
        {
            return false;
        }

        if (trimmed.Contains("function", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("var ", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("MenuPage", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !LooksLikeLabel(trimmed);
    }

    public static bool LooksLikeLabel(string value)
    {
        var compact = Compact(value);
        if (compact is "TXTRANSMIT" or "RXRECEIVE" or "TRANSMIT" or "RECEIVE" or "TRANSMITTERBIASCURRENT")
        {
            return true;
        }

        if (compact.Contains("TRANSMIT") && compact.Contains("RECEIVE"))
        {
            return true;
        }

        return !value.Any(char.IsDigit)
               && (compact.Contains("TRANSMIT")
                   || compact.Contains("RECEIVE")
                   || compact.Contains("OPTICALMODULE")
                   || compact == "CURRENT"
                   || compact == "VOLTAGE"
                   || compact == "TEMPERATURE");
    }

    public static ParsedField Evidence(
        string field,
        string value,
        string page,
        string strategy,
        string? key,
        string? hash)
        => new(
            value.Trim(),
            new FieldEvidence(field, value.Trim(), page, strategy, field + "=" + value.Trim())
            {
                EndpointType = EndpointTypeOf(page),
                FieldKey = key,
                ResponseHash = hash
            });

    private static string? EndpointTypeOf(string page)
    {
        var match = Regex.Match(page, @"[?&]_type=([^&]+)", RegexOptions.IgnoreCase);
        return match.Success ? Uri.UnescapeDataString(match.Groups[1].Value) : null;
    }
}
