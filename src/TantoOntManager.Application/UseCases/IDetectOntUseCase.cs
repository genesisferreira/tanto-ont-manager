using System.Net;
using TantoOntManager.Domain.Detection;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.Application.UseCases;

public sealed record DetectOntCommand(
    EthernetAdapterInfo? Adapter,
    IPAddress TargetAddress,
    bool TrustLocalCertificate);

public interface IDetectOntUseCase
{
    Task<DetectionReport> ExecuteAsync(DetectOntCommand command, CancellationToken cancellationToken);
}
