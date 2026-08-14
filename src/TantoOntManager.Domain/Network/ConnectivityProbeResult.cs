using TantoOntManager.Domain.Network;

namespace TantoOntManager.Domain.Network;

public sealed record ConnectivityProbeResult(
    OntEndpoint Endpoint,
    bool IcmpReachable,
    bool HttpsReachable,
    bool HttpReachable,
    int? HttpsStatusCode,
    int? HttpStatusCode,
    string? PageTitle,
    string? ServerHeader,
    string? BodySnippet,
    string? TlsNote,
    TimeSpan Duration,
    string? ErrorMessage)
{
    public bool AnyHttpReachable => HttpsReachable || HttpReachable;
}
