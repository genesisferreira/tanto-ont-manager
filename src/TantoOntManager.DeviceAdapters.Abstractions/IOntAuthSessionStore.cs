using System.Net;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Abstractions;

public interface IOntAuthSessionStore
{
    AuthorizedDeviceSession? DomainSession { get; }

    IBoundOntTransport? Transport { get; }

    AuthenticatedReadSnapshot? Snapshot { get; }

    AuthenticatedReadMap? ReadMap { get; }

    AuthSessionState State { get; }

    void Remember(
        IBoundOntTransport transport,
        AuthorizedDeviceSession session,
        AuthenticatedReadSnapshot snapshot);

    void RememberReadMap(AuthenticatedReadMap map);

    void ReplaceSnapshot(AuthenticatedReadSnapshot snapshot);

    void End(string reason);

    void SetState(AuthSessionState state);

    bool IsBoundTo(IPAddress address, string? certificateSha256);
}
