using System.Net;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.DeviceAdapters.Abstractions;

public sealed record BoundHttpResult(
    bool Succeeded,
    int StatusCode,
    string Body,
    string? ContentType,
    string FinalUri,
    int RedirectCount,
    string SanitizedBodySha256,
    TimeSpan Duration,
    Error? Error)
{
    public static BoundHttpResult Fail(Error error, int statusCode = 0, TimeSpan duration = default, int redirectCount = 0)
        => new(false, statusCode, string.Empty, null, string.Empty, redirectCount, string.Empty, duration, error);
}

public interface IBoundOntTransport : IDisposable
{
    IPAddress BoundAddress { get; }

    string? ObservedCertificateSha256 { get; }

    bool HasSessionCookie { get; }

    int PostCount { get; }

    int LoginPostCount { get; }

    int LogoutPostCount { get; }

    int ConfigPostCount { get; }

    string? SessionToken { get; }

    string SessionId { get; }

    int HttpClientInstanceId { get; }

    int CookieCount { get; }

    IReadOnlyList<string> HttpMethodsUsed { get; }

    IReadOnlyList<string> MaskedGetPages { get; }

    IReadOnlyList<string> MaskedPosts { get; }

    Task<BoundHttpResult> GetAsync(string pathAndQuery, CancellationToken cancellationToken);

    Task<BoundHttpResult> PostLoginFormAsync(
        IReadOnlyDictionary<string, string> form,
        CancellationToken cancellationToken);

    Task<BoundHttpResult> PostLogoutFormAsync(
        IReadOnlyDictionary<string, string> form,
        CancellationToken cancellationToken);

    void RememberSafeRead(string type, string tag);

    void ClearCookiesAndState(string reason);
}

public interface IBoundOntTransportFactory
{
    IBoundOntTransport Create(OntEndpoint endpoint, string? pinnedCertificateSha256);
}
