using System.Text.RegularExpressions;

namespace TantoOntManager.Domain.Observation;

public static class WriteContractContentInspector
{
    public static readonly IReadOnlyList<string> AllowedEntryNames =
    [
        "write-contract-proposal.json",
        "write-contract-summary.txt",
        "blocked-request.json",
        "manifest.json"
    ];

    public static ObservationZipInspection Inspect(string text, IReadOnlyList<string> entryNames)
    {
        var cookies = Regex.IsMatch(text, "(?i)(set-cookie\\s*:|SID_HTTPS_=)");
        var credentials = HasRawSecretAssignment(text, "password|senha|pwd");
        var tokens = Regex.IsMatch(text, "(?i)_sessionTOKEN=(?!\\[redacted\\])[^\\s\"&,]+")
                     || HasRawSecretAssignment(text, "challenge|token|sid");
        var html = Regex.IsMatch(text, "(?i)<html|</html>");
        var rawBody = Regex.IsMatch(text, "(?i)(raw(request)?body|requestbody|bodyraw)\\s*[:=]")
                      || Regex.IsMatch(text, "(?i)(Username|PPPUserName|UserName)=[^&\\s\"]{2,}");
        var authorization = Regex.IsMatch(text, "(?i)authorization\\s*[:=]\\s*(?!\\[redacted\\])\\S+");
        var fullHeaders = Regex.IsMatch(text, "(?i)\"headers\"\\s*:\\s*\\{");
        var namesAllowed = entryNames.Count > 0
                           && entryNames.All(name => AllowedEntryNames.Contains(name, StringComparer.OrdinalIgnoreCase));
        var masked = namesAllowed && !cookies && !credentials && !tokens && !html && !rawBody && !authorization && !fullHeaders;
        return new ObservationZipInspection(
            cookies,
            credentials,
            tokens,
            html,
            masked,
            0,
            entryNames,
            rawBody,
            authorization,
            fullHeaders,
            true,
            html);
    }

    public static bool LooksUnsafe(string text)
        => !Inspect(text, AllowedEntryNames).IsAcceptable;

    private static bool HasRawSecretAssignment(string text, string names)
        => Regex.IsMatch(text, "(?i)(" + names + ")\\s*[:=]\\s*(?!\\[redacted\\]|\"\\[redacted\\]\")\\S+");
}
