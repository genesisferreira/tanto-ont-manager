using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.Domain.Detection;

public sealed record DetectionReport(
    EthernetAdapterInfo? Adapter,
    ConnectivityProbeResult? Connectivity,
    DetectedDevice? Device,
    DeviceCapabilities? Capabilities,
    DeviceDiagnostics? PublicDiagnostics,
    IReadOnlyList<OperatorRecommendation> Recommendations,
    ApplicationStatus Status,
    TimeSpan Duration,
    DetectionConfidence Confidence = DetectionConfidence.Insufficient,
    IReadOnlyList<string>? Evidence = null,
    HttpPublicObservation? PublicObservation = null)
{
    public bool SubnetMismatch => Recommendations.Any(item => item.Code == "SUBNET");

    public IReadOnlyList<string> EvidenceList => Evidence ?? Device?.Evidence ?? [];
}
