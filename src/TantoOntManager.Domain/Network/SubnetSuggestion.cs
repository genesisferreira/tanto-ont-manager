using System.Net;

namespace TantoOntManager.Domain.Network;

public sealed record SubnetSuggestion(
    IPAddress SuggestedHostAddress,
    IPAddress SubnetMask,
    IPAddress Gateway,
    string Explanation)
{
    public static SubnetSuggestion? ForTarget(IPAddress target)
    {
        if (target.Equals(KnownOntAddresses.ZteLocal100))
        {
            return new SubnetSuggestion(
                IPAddress.Parse("192.168.100.10"),
                IPAddress.Parse("255.255.255.0"),
                KnownOntAddresses.ZteLocal100,
                "O computador não está na mesma sub-rede da ONT 192.168.100.1. Configure manualmente a placa Ethernet (o aplicativo não altera a interface nesta fase).");
        }

        if (target.Equals(KnownOntAddresses.CommonGateway1))
        {
            return new SubnetSuggestion(
                IPAddress.Parse("192.168.1.10"),
                IPAddress.Parse("255.255.255.0"),
                KnownOntAddresses.CommonGateway1,
                "O computador não está na mesma sub-rede da ONT 192.168.1.1. Configure manualmente a placa Ethernet (o aplicativo não altera a interface nesta fase).");
        }

        var bytes = target.GetAddressBytes();
        if (bytes.Length != 4)
        {
            return null;
        }

        bytes[3] = 10;
        return new SubnetSuggestion(
            new IPAddress(bytes),
            IPAddress.Parse("255.255.255.0"),
            target,
            "O computador não está na mesma sub-rede do IP informado. Ajuste a placa Ethernet manualmente; o aplicativo não aplica essa configuração.");
    }

    public string ToOperatorText()
        => $"{Explanation}{Environment.NewLine}{Environment.NewLine}" +
           $"IP sugerido: {SuggestedHostAddress}{Environment.NewLine}" +
           $"Máscara: {SubnetMask}{Environment.NewLine}" +
           $"Gateway: {Gateway}";
}
