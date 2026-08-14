using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Abstractions;

/// <summary>
/// Contrato separado da leitura. Envia a credencial somente no endpoint
/// homologado do adaptador específico, uma vez por clique em Login.
/// </summary>
public interface IOntAuthenticationAdapter
{
    string AdapterId { get; }

    bool CanAttemptAuthentication(AdapterProbeResult probe);

    Task<AuthenticationResult> AuthenticateAsync(
        OntEndpoint endpoint,
        AdapterProbeResult probe,
        DeviceCredentials credentials,
        string? pinnedCertificateSha256,
        CancellationToken cancellationToken);
}
