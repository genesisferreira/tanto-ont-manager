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

    private AuthorizedDeviceSession(
        Guid sessionId,
        OntEndpoint endpoint,
        DateTimeOffset establishedAt,
        bool isAuthenticated,
        string authenticationMethod)
    {
        SessionId = sessionId;
        Endpoint = endpoint;
        EstablishedAt = establishedAt;
        IsAuthenticated = isAuthenticated;
        AuthenticationMethod = authenticationMethod;
    }

    public static AuthorizedDeviceSession Public(OntEndpoint endpoint)
        => new(Guid.NewGuid(), endpoint, DateTimeOffset.UtcNow, false, "public-unauthenticated");

    public IPAddress Address => Endpoint.Address;
}
