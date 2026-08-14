using TantoOntManager.Domain.Network;

namespace TantoOntManager.DeviceAdapters.Abstractions;

public sealed record PublicWebDocument(
    OntEndpoint Endpoint,
    int StatusCode,
    string? Title,
    string? ServerHeader,
    string Body);

public interface IPublicWebReader
{
    Task<PublicWebDocument?> GetRootAsync(OntEndpoint endpoint, CancellationToken cancellationToken);
}
