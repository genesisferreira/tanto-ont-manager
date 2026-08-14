using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.Application.UseCases;

public sealed record AuthenticateCommand(
    OntEndpoint Endpoint,
    AdapterProbeResult Probe,
    DeviceCredentials Credentials,
    bool TrustLocalCertificate = true,
    string? PinnedCertificateSha256 = null);

public interface IAuthenticateDeviceUseCase
{
    Task<AuthenticationResult> ExecuteAsync(AuthenticateCommand command, CancellationToken cancellationToken);
}
