using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Audit;

namespace TantoOntManager.Application.UseCases;

public sealed class AuthenticateDeviceUseCase : IAuthenticateDeviceUseCase
{
    private readonly IReadOnlyList<IOntAuthenticationAdapter> _authAdapters;
    private readonly ISecureCredentialStore _credentialStore;
    private readonly IAuditLogService _auditLog;
    private readonly ILogger<AuthenticateDeviceUseCase> _logger;

    public AuthenticateDeviceUseCase(
        IEnumerable<IOntAuthenticationAdapter> authAdapters,
        ISecureCredentialStore credentialStore,
        IAuditLogService auditLog,
        ILogger<AuthenticateDeviceUseCase> logger)
    {
        _authAdapters = authAdapters.ToList();
        _credentialStore = credentialStore;
        _auditLog = auditLog;
        _logger = logger;
    }

    public async Task<AuthenticationResult> ExecuteAsync(
        AuthenticateCommand command,
        CancellationToken cancellationToken)
    {
        try
        {
            var adapter = _authAdapters.FirstOrDefault(item => item.AdapterId == command.Probe.AdapterId);
            if (adapter is null || !adapter.CanAttemptAuthentication(command.Probe))
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
                    "Autenticação não mapeada para o adaptador {AdapterId} em {Target}",
                    command.Probe.AdapterId,
                    command.Endpoint.Address);

                return result;
            }

            return await adapter.AuthenticateAsync(
                command.Endpoint,
                command.Probe,
                command.Credentials,
                cancellationToken);
        }
        finally
        {
            _credentialStore.Forget(command.Credentials);
        }
    }
}
