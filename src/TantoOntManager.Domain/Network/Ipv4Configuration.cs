using System.Net;

namespace TantoOntManager.Domain.Network;

public sealed record Ipv4Configuration(IPAddress Address, IPAddress SubnetMask)
{
    public IPAddress NetworkAddress
    {
        get
        {
            var addressBytes = Address.GetAddressBytes();
            var maskBytes = SubnetMask.GetAddressBytes();
            var networkBytes = new byte[4];
            for (var i = 0; i < 4; i++)
            {
                networkBytes[i] = (byte)(addressBytes[i] & maskBytes[i]);
            }

            return new IPAddress(networkBytes);
        }
    }

    public bool IsInSameSubnet(IPAddress other)
    {
        var otherBytes = other.GetAddressBytes();
        var addressBytes = Address.GetAddressBytes();
        var maskBytes = SubnetMask.GetAddressBytes();
        if (otherBytes.Length != 4 || addressBytes.Length != 4)
        {
            return false;
        }

        for (var i = 0; i < 4; i++)
        {
            if ((addressBytes[i] & maskBytes[i]) != (otherBytes[i] & maskBytes[i]))
            {
                return false;
            }
        }

        return true;
    }
}
