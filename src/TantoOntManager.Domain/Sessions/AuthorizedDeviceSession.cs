using System.Net;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.Domain.Sessions;

public sealed class AuthorizedDeviceSession
{
    public Guid SessionId { get; }
    public OntEndpoint Endpoint { get; }
    public DateTimeOffset EstablishedAt { get; }
    public bool IsAuthenticated { get; }
    public string AuthenticationMethod { get; }
    public string? BoundCertificateSha256 { get; }

    private AuthorizedDeviceSession(
        Guid sessionId,
        OntEndpoint endpoint,
        DateTimeOffset establishedAt,
        bool isAuthenticated,
        string authenticationMethod,
        string? boundCertificateSha256)
    {
        SessionId = sessionId;
        Endpoint = endpoint;
        EstablishedAt = establishedAt;
        IsAuthenticated = isAuthenticated;
        AuthenticationMethod = authenticationMethod;
        BoundCertificateSha256 = boundCertificateSha256;
    }

    public static AuthorizedDeviceSession Public(OntEndpoint endpoint)
        => new(Guid.NewGuid(), endpoint, DateTimeOffset.UtcNow, false, "public-unauthenticated", null);

    public static AuthorizedDeviceSession Authenticated(
        OntEndpoint endpoint,
        string authenticationMethod,
        string? boundCertificateSha256)
        => new(Guid.NewGuid(), endpoint, DateTimeOffset.UtcNow, true, authenticationMethod, boundCertificateSha256);

    public IPAddress Address => Endpoint.Address;

    public bool IsBoundTo(IPAddress address, string? certificateSha256)
    {
        if (!Address.Equals(address))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(BoundCertificateSha256) || string.IsNullOrWhiteSpace(certificateSha256))
        {
            return string.Equals(BoundCertificateSha256, certificateSha256, StringComparison.OrdinalIgnoreCase);
        }

        return BoundCertificateSha256.Equals(certificateSha256, StringComparison.OrdinalIgnoreCase);
    }
}
