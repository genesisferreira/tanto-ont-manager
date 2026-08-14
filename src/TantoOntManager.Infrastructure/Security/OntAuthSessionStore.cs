using Microsoft.Extensions.Logging;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.Infrastructure.Security;

public sealed class OntAuthSessionStore : IOntAuthSessionStore
{
    private readonly ILogger<OntAuthSessionStore> _logger;
    private readonly object _gate = new();
    private IBoundOntTransport? _transport;
    private AuthorizedDeviceSession? _session;
    private AuthenticatedReadSnapshot? _snapshot;
    private AuthenticatedReadMap? _readMap;
    private AuthSessionState _state = AuthSessionState.Unmapped;

    public OntAuthSessionStore(ILogger<OntAuthSessionStore> logger)
    {
        _logger = logger;
    }

    public AuthorizedDeviceSession? DomainSession
    {
        get
        {
            lock (_gate)
            {
                return _session;
            }
        }
    }

    public IBoundOntTransport? Transport
    {
        get
        {
            lock (_gate)
            {
                return _transport;
            }
        }
    }

    public AuthenticatedReadSnapshot? Snapshot
    {
        get
        {
            lock (_gate)
            {
                return _snapshot;
            }
        }
    }

    public AuthenticatedReadMap? ReadMap
    {
        get
        {
            lock (_gate)
            {
                return _readMap;
            }
        }
    }

    public AuthSessionState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
        set
        {
            lock (_gate)
            {
                _state = value;
            }
        }
    }

    public void Remember(
        IBoundOntTransport transport,
        AuthorizedDeviceSession session,
        AuthenticatedReadSnapshot snapshot)
    {
        lock (_gate)
        {
            if (!ReferenceEquals(_transport, transport))
            {
                _transport?.Dispose();
            }

            _transport = transport;
            _session = session;
            _snapshot = snapshot;
            _readMap = null;
            _state = AuthSessionState.AuthenticatedReadOnly;
        }

        _logger.LogInformation(
            "Sessão autenticada em memória adapter={Adapter} posts={Posts} páginas={Pages}",
            snapshot.AdapterId,
            snapshot.PostCount,
            snapshot.PagesRead.Count);
    }

    public void RememberReadMap(AuthenticatedReadMap map)
    {
        lock (_gate)
        {
            _readMap = map;
        }

        _logger.LogInformation(
            "Mapa autenticado candidatos={Total} safe={Safe} bloqueados={Blocked} duplicados={Dup}",
            map.TotalCandidates,
            map.SafeReadCount,
            map.BlockedCount,
            map.DuplicateCount);
    }

    public void ReplaceSnapshot(AuthenticatedReadSnapshot snapshot)
    {
        lock (_gate)
        {
            _snapshot = snapshot;
        }
    }

    public void End(string reason)
    {
        lock (_gate)
        {
            _transport?.ClearCookiesAndState(reason);
            _transport?.Dispose();
            _transport = null;
            _session = null;
            _snapshot = null;
            _readMap = null;
            if (_state is AuthSessionState.AuthenticatedReadOnly or AuthSessionState.Authenticating)
            {
                _state = AuthSessionState.Unmapped;
            }
        }

        _logger.LogInformation("Sessão autenticada encerrada. motivo={Reason}", reason);
    }

    public void SetState(AuthSessionState state)
    {
        lock (_gate)
        {
            _state = state;
        }
    }

    public bool IsBoundTo(System.Net.IPAddress address, string? certificateSha256)
    {
        lock (_gate)
        {
            return _session?.IsBoundTo(address, certificateSha256) == true
                   && _transport is not null
                   && _transport.BoundAddress.Equals(address);
        }
    }
}
