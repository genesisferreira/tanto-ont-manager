using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.Application.UseCases;

public sealed record TestConnectionCommand(
    EthernetAdapterInfo? Adapter,
    System.Net.IPAddress TargetAddress,
    bool TrustLocalCertificate);

public interface ITestConnectionUseCase
{
    Task<ConnectivityProbeResult> ExecuteAsync(TestConnectionCommand command, CancellationToken cancellationToken);
}

public interface IListEthernetAdaptersUseCase
{
    IReadOnlyList<EthernetAdapterInfo> Execute();
}
