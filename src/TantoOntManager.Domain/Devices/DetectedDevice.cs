using TantoOntManager.Domain.Network;

namespace TantoOntManager.Domain.Devices;

public sealed record DetectedDevice(
    OntEndpoint Endpoint,
    DeviceIdentity Identity,
    string AdapterId,
    double Confidence,
    IReadOnlyList<string> Evidence,
    bool RequiresAuthenticationForDetails)
{
    public string ConfidenceDisplay => Confidence switch
    {
        >= 0.85 => "Alta",
        >= 0.55 => "Média",
        _ => "Baixa"
    };
}
