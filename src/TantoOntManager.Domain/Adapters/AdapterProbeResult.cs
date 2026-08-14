using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.Domain.Adapters;

public sealed record ProbeEvidence(
    string Source,
    string Detail);

public sealed record AdapterProbeResult
{
    public bool Matched { get; init; }
    public string AdapterId { get; init; } = string.Empty;
    public string Manufacturer { get; init; } = ManufacturerNames.Unknown;
    public string? Model { get; init; }
    public double Confidence { get; init; }
    public OntEndpoint Endpoint { get; init; } = null!;
    public IReadOnlyList<ProbeEvidence> Evidence { get; init; } = [];
    public Error? Error { get; init; }
    public bool LoginFormVisible { get; init; }
    public bool HttpsUsed { get; init; }

    public static AdapterProbeResult NoMatch(string adapterId, OntEndpoint endpoint, Error? error = null)
        => new()
        {
            Matched = false,
            AdapterId = adapterId,
            Endpoint = endpoint,
            Error = error,
            Confidence = 0
        };

    public static AdapterProbeResult Match(
        string adapterId,
        string manufacturer,
        string? model,
        double confidence,
        OntEndpoint endpoint,
        IReadOnlyList<ProbeEvidence> evidence,
        bool loginFormVisible,
        bool httpsUsed)
        => new()
        {
            Matched = true,
            AdapterId = adapterId,
            Manufacturer = manufacturer,
            Model = model,
            Confidence = confidence,
            Endpoint = endpoint,
            Evidence = evidence,
            LoginFormVisible = loginFormVisible,
            HttpsUsed = httpsUsed
        };
}
