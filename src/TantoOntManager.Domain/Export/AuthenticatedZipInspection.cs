namespace TantoOntManager.Domain.Export;

public sealed record AuthenticatedZipInspection(
    bool IncludesCookies,
    bool IncludesCredentials,
    bool IncludesRawAuthenticatedHtml,
    bool SensitiveIdentifiersMasked,
    IReadOnlyList<string> EntryNames,
    bool IncludesTokens = false,
    bool IncludesRawAuthenticatedBody = false,
    int ConfigurationRequestsSent = 0)
{
    public bool IsAcceptable
        => !IncludesCookies
           && !IncludesCredentials
           && !IncludesRawAuthenticatedHtml
           && SensitiveIdentifiersMasked
           && !IncludesTokens
           && !IncludesRawAuthenticatedBody
           && ConfigurationRequestsSent == 0;

    public string ToOperatorText()
        => string.Join(Environment.NewLine, new[]
        {
            $"IncludesCookies: {IncludesCookies.ToString().ToLowerInvariant()}",
            $"IncludesCredentials: {IncludesCredentials.ToString().ToLowerInvariant()}",
            $"IncludesTokens: {IncludesTokens.ToString().ToLowerInvariant()}",
            $"IncludesRawAuthenticatedHtml: {IncludesRawAuthenticatedHtml.ToString().ToLowerInvariant()}",
            $"IncludesRawAuthenticatedBody: {IncludesRawAuthenticatedBody.ToString().ToLowerInvariant()}",
            $"SensitiveIdentifiersMasked: {SensitiveIdentifiersMasked.ToString().ToLowerInvariant()}",
            $"ConfigurationRequestsSent: {ConfigurationRequestsSent}"
        });
}

public sealed record AuthenticatedExportResult(
    string ZipPath,
    AuthenticatedZipInspection Inspection);
