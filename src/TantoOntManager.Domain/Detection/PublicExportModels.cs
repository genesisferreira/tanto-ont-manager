namespace TantoOntManager.Domain.Detection;

public sealed record ScoredEvidence(
    string Code,
    string Label,
    int Weight,
    bool IsManufacturer,
    bool IsModel);

public sealed record PublicExportManifest(
    string Product,
    string Version,
    DateTimeOffset CreatedAt,
    string TargetAddressMasked,
    string Scheme,
    int Port,
    int? StatusCode,
    string? FinalUri,
    int RedirectCount,
    string? Title,
    int BodyLengthBytes,
    string BodySha256,
    IReadOnlyList<string> HttpMethodsUsed,
    bool IncludesCookies,
    bool IncludesCredentials);
