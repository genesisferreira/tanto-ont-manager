using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Abstractions;

public interface IOntDeviceAdapter
{
    string AdapterId { get; }
    string Manufacturer { get; }
    IReadOnlyCollection<string> SupportedModels { get; }

    Task<AdapterProbeResult> ProbeAsync(
        OntEndpoint endpoint,
        CancellationToken cancellationToken);

    Task<DeviceIdentityResult> ReadIdentityAsync(
        AuthorizedDeviceSession session,
        CancellationToken cancellationToken);

    Task<DeviceDiagnosticsResult> ReadDiagnosticsAsync(
        AuthorizedDeviceSession session,
        CancellationToken cancellationToken);

    Task<DeviceCapabilitiesResult> ReadCapabilitiesAsync(
        AuthorizedDeviceSession session,
        CancellationToken cancellationToken);
}
