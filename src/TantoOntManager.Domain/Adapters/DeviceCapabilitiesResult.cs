using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;

namespace TantoOntManager.Domain.Adapters;

public sealed record DeviceCapabilitiesResult
{
    public bool Succeeded { get; init; }
    public DeviceCapabilities? Capabilities { get; init; }
    public Error? Error { get; init; }

    public static DeviceCapabilitiesResult Success(DeviceCapabilities capabilities)
        => new() { Succeeded = true, Capabilities = capabilities };

    public static DeviceCapabilitiesResult Failure(Error error)
        => new() { Succeeded = false, Error = error };
}
