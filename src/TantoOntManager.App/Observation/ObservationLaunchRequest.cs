using System.IO;
using System.Net;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.App.Observation;

public sealed record ObservationLaunchRequest(
    IPAddress BoundAddress,
    Uri StartUri,
    IReadOnlyList<IsolatedObserverCookie> Cookies,
    string UserDataFolder,
    string? Manufacturer = null,
    string? Model = null,
    FirmwareCompatibility Firmware = FirmwareCompatibility.Unconfirmed,
    string? SoftwareVersion = null,
    bool Authenticated = false,
    string? Username = null,
    IReadOnlyList<string>? WanProfiles = null)
{
    public WriteCaptureEligibilityInput WriteEligibility(string? confirmation)
        => new(Manufacturer, Model, Firmware, SoftwareVersion, Authenticated, confirmation);

    public WriteCapabilityContext CapabilityContext()
        => new(Manufacturer, Model, Firmware, SoftwareVersion, Username, WanProfiles ?? []);
}
