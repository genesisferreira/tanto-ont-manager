namespace TantoOntManager.Domain.Network;

public enum TlsErrorCategory
{
    None = 0,
    UntrustedRoot = 1,
    NameMismatch = 2,
    CertificateNotAvailable = 3,
    HandshakeFailed = 4,
    Other = 5
}

public sealed record CertificateObservation(
    string? Subject,
    string? Issuer,
    DateTimeOffset? NotBefore,
    DateTimeOffset? NotAfter,
    string? Sha256Fingerprint,
    bool AcceptedByLocalException,
    TlsErrorCategory ErrorCategory)
{
    public static CertificateObservation None { get; } = new(
        null, null, null, null, null, false, TlsErrorCategory.None);
}

public sealed record HttpPublicObservation(
    string TargetAddress,
    string Scheme,
    int Port,
    string Method,
    int? StatusCode,
    string? FinalUri,
    int RedirectCount,
    string? ContentType,
    string? Charset,
    int BodyLengthBytes,
    string? Title,
    string? BodySha256,
    TimeSpan ConnectDuration,
    TimeSpan TotalDuration,
    bool TimedOut,
    CertificateObservation Certificate,
    bool ContentWasCompressed,
    string? DetectedEncoding,
    IReadOnlyList<string> SafeHeaders,
    IReadOnlyList<string> FrameUris,
    IReadOnlyList<string> HttpMethodsUsed)
{
    public string ShortHash => string.IsNullOrWhiteSpace(BodySha256) ? "—" : BodySha256[..Math.Min(8, BodySha256.Length)];

    public string StatusDisplay => StatusCode is null ? "Sem resposta" : $"{Scheme.ToUpperInvariant()} {StatusCode}";
}
