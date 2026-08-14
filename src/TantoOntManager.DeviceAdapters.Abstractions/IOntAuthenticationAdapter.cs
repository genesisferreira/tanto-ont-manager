using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Abstractions;

/// <summary>
/// Contrato separado da leitura. Não envia credenciais enquanto o método de login
/// da firmware não estiver homologado.
/// </summary>
public interface IOntAuthenticationAdapter
{
    string AdapterId { get; }

    bool CanAttemptAuthentication(AdapterProbeResult probe);

    Task<AuthenticationResult> AuthenticateAsync(
        OntEndpoint endpoint,
        AdapterProbeResult probe,
        DeviceCredentials credentials,
        CancellationToken cancellationToken);
}
