using System.Net;

namespace TantoOntManager.Domain.Network;

public static class KnownOntAddresses
{
    public static readonly IPAddress ZteLocal100 = IPAddress.Parse("192.168.100.1");
    public static readonly IPAddress CommonGateway1 = IPAddress.Parse("192.168.1.1");

    public static IReadOnlyList<IPAddress> DefaultProbeTargets { get; } =
    [
        ZteLocal100,
        CommonGateway1
    ];

    public static bool IsKnownOrExplicitlyProvided(IPAddress address, IPAddress? customAddress)
    {
        if (DefaultProbeTargets.Any(known => known.Equals(address)))
        {
            return true;
        }

        return customAddress is not null && customAddress.Equals(address);
    }
}
