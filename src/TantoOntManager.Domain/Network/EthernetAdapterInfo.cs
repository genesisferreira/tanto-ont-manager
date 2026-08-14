namespace TantoOntManager.Domain.Network;

public sealed record EthernetAdapterInfo(
    string Id,
    string Name,
    string Description,
    bool HasPhysicalLink,
    Ipv4Configuration? Ipv4,
    string OperationalStatus)
{
    public string Ipv4Display => Ipv4?.Address.ToString() ?? "Não atribuído";

    public string LinkDisplay => HasPhysicalLink ? "Cabo detectado" : "Sem link físico";
}
