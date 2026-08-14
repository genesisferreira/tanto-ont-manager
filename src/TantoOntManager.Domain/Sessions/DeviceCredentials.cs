using System.Security;

namespace TantoOntManager.Domain.Sessions;

public sealed class DeviceCredentials : IDisposable
{
    public string Username { get; }
    public SecureString Password { get; }
    public bool PersistRequested { get; }

    private bool _disposed;

    public DeviceCredentials(string username, SecureString password, bool persistRequested)
    {
        Username = username;
        Password = password;
        PersistRequested = persistRequested;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Password.Dispose();
    }
}
