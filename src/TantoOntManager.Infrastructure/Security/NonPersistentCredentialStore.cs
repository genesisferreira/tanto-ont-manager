using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.Infrastructure.Security;

public sealed class NonPersistentCredentialStore : ISecureCredentialStore
{
    private readonly ILogger<NonPersistentCredentialStore> _logger;

    public NonPersistentCredentialStore(ILogger<NonPersistentCredentialStore> logger)
    {
        _logger = logger;
    }

    public bool PersistenceEnabled => false;

    public void Forget(DeviceCredentials credentials)
    {
        credentials.Dispose();
        _logger.LogInformation("Credencial descartada da memória. Persistência em disco está desabilitada nesta fase.");
    }
}
