using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.Application.Contracts;

public interface ISecureCredentialStore
{
    bool PersistenceEnabled { get; }

    void Forget(DeviceCredentials credentials);
}
