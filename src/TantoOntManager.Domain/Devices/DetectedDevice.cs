using TantoOntManager.Domain.Detection;
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
    public string ConfidenceDisplay => DetectionConfidenceDisplay.FromScore(Confidence, false).ToUiLabel();
}
