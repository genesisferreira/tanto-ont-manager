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
    string? ErrorMessage,
    HttpPublicObservation? HttpsObservation = null,
    HttpPublicObservation? HttpObservation = null)
{
    public bool AnyHttpReachable => HttpsReachable || HttpReachable;

    public HttpPublicObservation? PrimaryObservation => HttpsReachable ? HttpsObservation : HttpObservation;
}
