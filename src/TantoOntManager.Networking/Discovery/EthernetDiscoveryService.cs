using System.Net.NetworkInformation;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.Networking.Discovery;

public sealed class EthernetDiscoveryService : IEthernetDiscoveryService
{
    public IReadOnlyList<EthernetAdapterInfo> ListEthernetAdapters()
    {
        var adapters = new List<EthernetAdapterInfo>();

        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!IsEthernet(networkInterface))
            {
                continue;
            }

            var ipProps = networkInterface.GetIPProperties();
            var ipv4 = ipProps.UnicastAddresses
                .FirstOrDefault(item => item.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                                        && !System.Net.IPAddress.IsLoopback(item.Address));

            Ipv4Configuration? configuration = null;
            if (ipv4 is not null && ipv4.IPv4Mask is not null)
            {
                configuration = new Ipv4Configuration(ipv4.Address, ipv4.IPv4Mask);
            }

            adapters.Add(new EthernetAdapterInfo(
                networkInterface.Id,
                networkInterface.Name,
                networkInterface.Description,
                networkInterface.OperationalStatus == OperationalStatus.Up,
                configuration,
                networkInterface.OperationalStatus.ToString()));
        }

        return adapters
            .OrderByDescending(item => item.HasPhysicalLink)
            .ThenBy(item => item.Name)
            .ToList();
    }

    private static bool IsEthernet(NetworkInterface networkInterface)
    {
        if (networkInterface.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
        {
            return false;
        }

        return networkInterface.NetworkInterfaceType is NetworkInterfaceType.Ethernet
            or NetworkInterfaceType.GigabitEthernet
            or NetworkInterfaceType.FastEthernetT
            or NetworkInterfaceType.FastEthernetFx
            or NetworkInterfaceType.Ethernet3Megabit;
    }
}
