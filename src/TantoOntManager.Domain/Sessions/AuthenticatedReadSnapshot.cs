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
    int ConfigPostCount);
