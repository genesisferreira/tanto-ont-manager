using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;

namespace TantoOntManager.Domain.Adapters;

public sealed record DeviceIdentityResult
{
    public bool Succeeded { get; init; }
    public DeviceIdentity? Identity { get; init; }
    public Error? Error { get; init; }
    public bool RequiresAuthentication { get; init; }

    public static DeviceIdentityResult Success(DeviceIdentity identity)
        => new() { Succeeded = true, Identity = identity };

    public static DeviceIdentityResult Unavailable(Error error, bool requiresAuthentication)
        => new()
        {
            Succeeded = false,
            Error = error,
            RequiresAuthentication = requiresAuthentication
        };
}
