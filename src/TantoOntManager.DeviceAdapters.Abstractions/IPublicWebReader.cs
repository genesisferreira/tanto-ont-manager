using TantoOntManager.Domain.Network;

namespace TantoOntManager.DeviceAdapters.Abstractions;

public sealed record PublicWebDocument(
    OntEndpoint Endpoint,
    int StatusCode,
    string? Title,
    string? ServerHeader,
    string Body,
    HttpPublicObservation? Observation = null,
    IReadOnlyList<string>? HttpMethodsUsed = null)
{
    public IReadOnlyList<string> Methods => HttpMethodsUsed ?? ["GET"];
}

public interface IPublicWebReader
{
    Task<PublicWebDocument?> GetRootAsync(OntEndpoint endpoint, CancellationToken cancellationToken);
}

public interface IPublicProbeCache
{
    PublicWebDocument? LastDocument { get; }

    HttpPublicObservation? LastObservation { get; }

    void Remember(PublicWebDocument document, HttpPublicObservation? observation);
}
