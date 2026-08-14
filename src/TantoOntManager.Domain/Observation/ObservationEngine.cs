using System.Net;
using System.Text;

namespace TantoOntManager.Domain.Observation;

public sealed class ObservationEngine : IDisposable
{
    private readonly object _gate = new();
    private readonly List<ObservedGetRecord> _gets = [];
    private readonly List<BlockedRequestRecord> _blocked = [];
    private readonly List<ResponseStructure> _structures = [];
    private readonly Dictionary<string, string> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;
    private readonly IPAddress _boundAddress;
    private ObservationScreen _screen = ObservationScreen.Shell;
    private DateTimeOffset? _captureUntil;
    private bool _cancelled;
    private bool _endedByIpChange;
    private bool _baselineClosed;
    private int _sequence;
    private int _getsObserved;
    private int _getsAllowed;
    private int _blockedCount;
    private int _postsBlocked;

    public ObservationEngine(IPAddress boundAddress)
    {
        _boundAddress = boundAddress;
    }

    public IPAddress BoundAddress => _boundAddress;

    public TimeSpan CaptureWindow { get; } = TimeSpan.FromSeconds(ObservationScreens.CaptureSeconds);

    public ObservationDecision Evaluate(IncomingObservationRequest request)
    {
        lock (_gate)
        {
            var decision = ObservationRequestGate.Evaluate(request, _boundAddress, _cancelled || _endedByIpChange);
            var method = (request.Method ?? string.Empty).Trim().ToUpperInvariant();
            if (method is "GET" or "HEAD")
            {
                _getsObserved++;
            }

            if (method == "POST")
            {
                _postsBlocked++;
            }

            if (!decision.Allowed)
            {
                _blockedCount++;
                _blocked.Add(new BlockedRequestRecord(
                    ++_sequence,
                    DateTimeOffset.UtcNow - _started,
                    method,
                    ObservationUrl.PathSanitized(request.Uri),
                    decision.Reason,
                    request.Uri.Host));
                if (decision.EndsObservation && !ObservationHosts.IsBoundHost(request.Uri, _boundAddress))
                {
                    _endedByIpChange = true;
                    _cancelled = true;
                }
            }

            return decision;
        }
    }

    public ObservedGetRecord? CompleteGet(
        IncomingObservationRequest request,
        int statusCode,
        string? contentType,
        string? body,
        string? initiator)
    {
        lock (_gate)
        {
            if (_cancelled)
            {
                return null;
            }

            var method = (request.Method ?? string.Empty).Trim().ToUpperInvariant();
            if (method is not ("GET" or "HEAD"))
            {
                return null;
            }

            _getsAllowed++;
            var normalized = ObservationUrl.Normalize(request.Uri);
            var hash = ObservationSanitizer.Sha256(body);
            var classification = ObservationClassifier.Classify(
                request.Uri,
                new ObservationDecision(true, "permitido"));
            var inCapture = _baselineClosed
                            && _captureUntil is not null
                            && DateTimeOffset.UtcNow <= _captureUntil.Value;
            var screen = inCapture ? _screen : ObservationScreen.Shell;
            var isBaseline = !_baselineClosed;
            var changed = _baseline.TryGetValue(normalized, out var previous)
                          && !string.Equals(previous, hash, StringComparison.OrdinalIgnoreCase);
            var isNew = !_baseline.ContainsKey(normalized);
            if (isBaseline)
            {
                _baseline[normalized] = hash;
            }

            var isNewOrChanged = _baselineClosed && (isNew || changed);
            if (classification == ObservedGetClassification.Asset && !changed && !isNew)
            {
                isNewOrChanged = false;
            }

            var record = new ObservedGetRecord(
                ++_sequence,
                DateTimeOffset.UtcNow - _started,
                screen,
                ObservationUrl.PathSanitized(request.Uri),
                ObservationUrl.TypeOf(request.Uri),
                ObservationUrl.TagOf(request.Uri),
                ObservationUrl.ExtraNames(request.Uri),
                ObservationUrl.ExtraValuesSanitized(request.Uri),
                method,
                statusCode,
                contentType,
                body?.Length ?? 0,
                hash,
                ObservationSanitizer.SanitizeText(initiator),
                classification,
                isBaseline && !_baselineClosed,
                isNewOrChanged,
                normalized);

            _gets.Add(record);
            if (classification == ObservedGetClassification.DataEndpoint && !string.IsNullOrEmpty(body))
            {
                _structures.Add(ResponseStructureInspector.Inspect(normalized, contentType, body));
            }

            return record;
        }
    }

    public void CloseBaseline()
    {
        lock (_gate)
        {
            _baselineClosed = true;
            _screen = ObservationScreen.Shell;
            _captureUntil = null;
        }
    }

    public void StartScreenCapture(ObservationScreen screen)
    {
        lock (_gate)
        {
            if (_cancelled)
            {
                return;
            }

            _baselineClosed = true;
            _screen = screen;
            _captureUntil = DateTimeOffset.UtcNow.Add(CaptureWindow);
        }
    }

    public void Cancel()
    {
        lock (_gate)
        {
            _cancelled = true;
            _captureUntil = null;
        }
    }

    public void EndBecauseIpChanged()
    {
        lock (_gate)
        {
            _endedByIpChange = true;
            _cancelled = true;
            _captureUntil = null;
        }
    }

    public bool IsCancelled
    {
        get
        {
            lock (_gate)
            {
                return _cancelled;
            }
        }
    }

    public bool EndedByIpChange
    {
        get
        {
            lock (_gate)
            {
                return _endedByIpChange;
            }
        }
    }

    public ObservationScreen CurrentScreen
    {
        get
        {
            lock (_gate)
            {
                return _screen;
            }
        }
    }

    public ObservationCounters Counters
    {
        get
        {
            lock (_gate)
            {
                return new ObservationCounters(_getsObserved, _getsAllowed, _blockedCount, _postsBlocked, 0);
            }
        }
    }

    public IReadOnlyList<ObservedGetRecord> Gets
    {
        get
        {
            lock (_gate)
            {
                return _gets.ToList();
            }
        }
    }

    public IReadOnlyList<BlockedRequestRecord> Blocked
    {
        get
        {
            lock (_gate)
            {
                return _blocked.ToList();
            }
        }
    }

    public IReadOnlyList<ResponseStructure> Structures
    {
        get
        {
            lock (_gate)
            {
                return _structures.ToList();
            }
        }
    }

    public IReadOnlyDictionary<string, string> Baseline
    {
        get
        {
            lock (_gate)
            {
                return new Dictionary<string, string>(_baseline, StringComparer.OrdinalIgnoreCase);
            }
        }
    }

    public string ToOperatorTable()
    {
        var lines = new List<string>
        {
            "Tela | Ordem | GET | Tipo/tag | Extras | HTTP | Content-Type | Tamanho | Hash | Novo/alterado | Classificação"
        };
        lock (_gate)
        {
            foreach (var item in _gets)
            {
                var extras = item.ExtraParameterNames.Count == 0
                    ? "—"
                    : string.Join(",", item.ExtraParameterNames);
                lines.Add(string.Join(" | ", new[]
                {
                    item.Screen.ToOperatorLabel(),
                    item.Sequence.ToString(),
                    item.Path,
                    string.IsNullOrWhiteSpace(item.Type) && string.IsNullOrWhiteSpace(item.Tag)
                        ? "—"
                        : $"{item.Type ?? "—"}/{item.Tag ?? "—"}",
                    extras,
                    item.StatusCode?.ToString() ?? "—",
                    item.ContentType ?? "—",
                    item.SizeBytes.ToString(),
                    item.Sha256.Length <= 12 ? item.Sha256 : item.Sha256[..12],
                    item.IsNewOrChanged ? "sim" : (item.IsBaseline ? "baseline" : "não"),
                    item.Classification.ToString()
                }));
            }
        }

        return string.Join(Environment.NewLine, lines);
    }

    public string ToSummaryText()
    {
        var counters = Counters;
        var builder = new StringBuilder();
        builder.AppendLine("Observação passiva de GETs dinâmicos (sanitizada)");
        builder.AppendLine("IP: " + ObservationSanitizer.SanitizeText(_boundAddress.ToString()));
        builder.AppendLine($"GET observados: {counters.GetsObserved}");
        builder.AppendLine($"GET permitidos: {counters.GetsAllowed}");
        builder.AppendLine($"Requisições bloqueadas: {counters.RequestsBlocked}");
        builder.AppendLine($"POST observados e bloqueados: {counters.PostsObservedAndBlocked}");
        builder.AppendLine("POST de configuração enviados: 0");
        builder.AppendLine();
        builder.AppendLine(ToOperatorTable());
        return ObservationSanitizer.SanitizeText(builder.ToString());
    }

    public ObservationSnapshot Snapshot()
    {
        lock (_gate)
        {
            return new ObservationSnapshot(
                _boundAddress,
                new ObservationCounters(_getsObserved, _getsAllowed, _blockedCount, _postsBlocked, 0),
                _gets.ToList(),
                _blocked.ToList(),
                _structures.ToList(),
                ToOperatorTable(),
                ToSummaryText());
        }
    }

    public void Dispose() => Cancel();
}
