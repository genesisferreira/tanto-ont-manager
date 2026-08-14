using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.Domain.Sessions;

public sealed record AuthenticatedReadSnapshot(
    DeviceIdentity Identity,
    DeviceDiagnostics Diagnostics,
    IReadOnlyList<string> PagesRead,
    int PostCount,
    int RedirectCount,
    string? LastStatus,
    string? LastSanitizedHash,
    TimeSpan AuthenticationDuration,
    string AdapterId,
    IReadOnlyList<SafeReadInventoryItem> Inventory,
    IReadOnlyList<FieldEvidence> FieldEvidence,
    int LoginPostCount,
    int LogoutPostCount,
    int ConfigPostCount)
{
    public FirmwareCompatibility FirmwareCompatibility { get; init; } = FirmwareCompatibility.Unconfirmed;

    public IReadOnlyList<FieldReadResult> FieldReads { get; init; } = [];

    public IReadOnlyList<HomologatedGetTrace> HomologatedGets { get; init; } = [];

    public string DiagnosticOperatorText()
    {
        var lines = new List<string>
        {
            "Leitura automática homologada (sanitizada)",
            $"GET: {HomologatedGets.Count}",
            $"POST login: {LoginPostCount}",
            $"POST logout: {LogoutPostCount}",
            $"POST configuração: {ConfigPostCount}"
        };
        foreach (var get in HomologatedGets)
        {
            lines.Add(get.ToOperatorLine());
        }

        return string.Join(Environment.NewLine, lines);
    }
}
