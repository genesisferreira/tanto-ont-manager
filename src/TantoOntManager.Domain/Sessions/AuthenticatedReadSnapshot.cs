using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;

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
    string AdapterId);
