using TantoOntManager.Domain.Devices;

namespace TantoOntManager.Domain.Diagnostics;

public sealed record DeviceDiagnostics(
    PonState Pon,
    OpticalReading Optical,
    IReadOnlyList<WanProfile> WanProfiles,
    string? WanSummary,
    bool SourceIsPublicInterface,
    string AvailabilityNote)
{
    public static DeviceDiagnostics PublicInterfaceOnly(string note)
        => new(
            PonState.Unknown,
            OpticalReading.Unavailable,
            [],
            null,
            true,
            note);
}
