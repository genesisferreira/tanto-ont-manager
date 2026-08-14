using TantoOntManager.Domain.Network;

namespace TantoOntManager.Application.Contracts;

public sealed record ProbeRequest(
    System.Net.IPAddress TargetAddress,
    EthernetAdapterInfo? Adapter,
    bool TrustLocalCertificate,
    TimeSpan Timeout);

public interface IConnectivityProbeService
{
    Task<ConnectivityProbeResult> ProbeAsync(ProbeRequest request, CancellationToken cancellationToken);
}
