using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.Infrastructure.Security;

public sealed class ObservationSessionStore : IObservationSessionStore
{
    private readonly object _gate = new();
    private ObservationEngine? _engine;
    private ObservationSnapshot? _snapshot;
    private string? _folder;
    private bool _open;
    private bool _destroyed = true;

    public ObservationEngine? Engine
    {
        get
        {
            lock (_gate)
            {
                return _engine;
            }
        }
    }

    public ObservationSnapshot? LastSnapshot
    {
        get
        {
            lock (_gate)
            {
                return _snapshot;
            }
        }
    }

    public string? UserDataFolder
    {
        get
        {
            lock (_gate)
            {
                return _folder;
            }
        }
    }

    public bool IsOpen
    {
        get
        {
            lock (_gate)
            {
                return _open;
            }
        }
    }

    public bool TemporaryCookiesDestroyed
    {
        get
        {
            lock (_gate)
            {
                return _destroyed;
            }
        }
    }

    public void Attach(ObservationEngine engine, string userDataFolder)
    {
        lock (_gate)
        {
            _engine?.Cancel();
            if (!string.IsNullOrWhiteSpace(_folder))
            {
                IsolatedObserverCleanup.DestroyUserDataFolder(_folder);
            }

            _engine = engine;
            _folder = userDataFolder;
            _open = true;
            _destroyed = false;
            _snapshot = null;
        }
    }

    public ObservationSnapshot FinishAndDestroy()
    {
        lock (_gate)
        {
            if (_engine is null && _folder is null && !_open)
            {
                _destroyed = true;
                return _snapshot ?? EmptySnapshot();
            }

            _engine?.Cancel();
            var snapshot = _engine?.Snapshot() ?? _snapshot;
            if (snapshot is not null)
            {
                _snapshot = snapshot;
            }

            _engine?.Dispose();
            _engine = null;
            _open = false;
            _destroyed = IsolatedObserverCleanup.DestroyUserDataFolder(_folder);
            _folder = null;
            return _snapshot ?? EmptySnapshot();
        }
    }

    private static ObservationSnapshot EmptySnapshot()
        => new(
            System.Net.IPAddress.None,
            ObservationCounters.Zero,
            [],
            [],
            [],
            string.Empty,
            string.Empty);

    public void ClearSnapshot()
    {
        lock (_gate)
        {
            if (_open)
            {
                FinishAndDestroy();
            }

            _snapshot = null;
        }
    }
}
