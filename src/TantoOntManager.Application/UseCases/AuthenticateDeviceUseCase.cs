using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Application.UseCases;

public sealed class AuthenticateDeviceUseCase : IAuthenticateDeviceUseCase
{
    private readonly IReadOnlyList<IOntAuthenticationAdapter> _authAdapters;
    private readonly ISecureCredentialStore _credentialStore;
    private readonly IAuditLogService _auditLog;
    private readonly ProbeSessionSettings _probeSessionSettings;
    private readonly ILogger<AuthenticateDeviceUseCase> _logger;

    public AuthenticateDeviceUseCase(
        IEnumerable<IOntAuthenticationAdapter> authAdapters,
        ISecureCredentialStore credentialStore,
        IAuditLogService auditLog,
        ProbeSessionSettings probeSessionSettings,
        ILogger<AuthenticateDeviceUseCase> logger)
    {
        _authAdapters = authAdapters.ToList();
        _credentialStore = credentialStore;
        _auditLog = auditLog;
        _probeSessionSettings = probeSessionSettings;
        _logger = logger;
    }

    public async Task<AuthenticationResult> ExecuteAsync(
        AuthenticateCommand command,
        CancellationToken cancellationToken)
    {
        try
        {
            _probeSessionSettings.Trust = command.TrustLocalCertificate
                ? LocalCertificateTrust.ForSelectedEndpoint(command.Endpoint.Address)
                : LocalCertificateTrust.Denied(command.Endpoint.Address);

            var adapter = _authAdapters.FirstOrDefault(item => item.CanAttemptAuthentication(command.Probe));
            if (adapter is null)
            {
                var result = AuthenticationResult.MethodNotMapped(
                    command.Probe.Manufacturer,
                    command.Probe.Model,
                    null);

                _auditLog.Record(AuditEvent.Create(
                    "authenticate",
                    "method-not-mapped",
                    command.Endpoint.Address.ToString(),
                    "Nenhuma credencial foi transmitida."));

                _logger.LogInformation(
                    "Autenticação não mapeada para o alvo {Target}",
                    command.Endpoint.Address);

                return result;
            }

            var auth = await adapter.AuthenticateAsync(
                command.Endpoint,
                command.Probe,
                command.Credentials,
                command.PinnedCertificateSha256,
                cancellationToken);

            _auditLog.Record(AuditEvent.Create(
                "authenticate",
                auth.SessionState.ToUiLabel(),
                command.Endpoint.Address.ToString(),
                $"status={auth.HttpStatus}; posts={auth.PostCount}; redirects={auth.RedirectCount}; hash={auth.SanitizedResponseHash}; endpoint={auth.MaskedEndpoint}"));

            _logger.LogInformation(
                "Autenticação concluída target={Target} estado={State} posts={Posts} status={Status} duracao={Duration}",
                command.Endpoint.Address,
                auth.SessionState,
                auth.PostCount,
                auth.HttpStatus,
                auth.Duration);

            return auth;
        }
        finally
        {
            _credentialStore.Forget(command.Credentials);
        }
    }
}
