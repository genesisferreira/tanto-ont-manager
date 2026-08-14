namespace TantoOntManager.Domain.Export;

public sealed record AuthenticatedZipInspection(
    bool IncludesCookies,
    bool IncludesCredentials,
    bool IncludesRawAuthenticatedHtml,
    bool SensitiveIdentifiersMasked,
    IReadOnlyList<string> EntryNames)
{
    public bool IsAcceptable
        => !IncludesCookies
           && !IncludesCredentials
           && !IncludesRawAuthenticatedHtml
           && SensitiveIdentifiersMasked;

    public string ToOperatorText()
        => string.Join(Environment.NewLine, new[]
        {
            $"IncludesCookies: {IncludesCookies.ToString().ToLowerInvariant()}",
            $"IncludesCredentials: {IncludesCredentials.ToString().ToLowerInvariant()}",
            $"IncludesRawAuthenticatedHtml: {IncludesRawAuthenticatedHtml.ToString().ToLowerInvariant()}",
            $"SensitiveIdentifiersMasked: {SensitiveIdentifiersMasked.ToString().ToLowerInvariant()}"
        });
}

public sealed record AuthenticatedExportResult(
    string ZipPath,
    AuthenticatedZipInspection Inspection);
