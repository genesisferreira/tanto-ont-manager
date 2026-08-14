using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Detection;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Application.UseCases;

public sealed class DetectOntUseCase : IDetectOntUseCase
{
    private readonly IConnectivityProbeService _probeService;
    private readonly IReadOnlyList<IOntDeviceAdapter> _adapters;
    private readonly IReadOnlyList<IOntAuthenticationAdapter> _authAdapters;
    private readonly IAuditLogService _auditLog;
    private readonly ProbeSessionSettings _probeSessionSettings;
    private readonly ILogger<DetectOntUseCase> _logger;

    public DetectOntUseCase(
        IConnectivityProbeService probeService,
        IEnumerable<IOntDeviceAdapter> adapters,
        IEnumerable<IOntAuthenticationAdapter> authAdapters,
        IAuditLogService auditLog,
        ProbeSessionSettings probeSessionSettings,
        ILogger<DetectOntUseCase> logger)
    {
        _probeService = probeService;
        _adapters = adapters.ToList();
        _authAdapters = authAdapters.ToList();
        _auditLog = auditLog;
        _probeSessionSettings = probeSessionSettings;
        _logger = logger;
    }

    public async Task<DetectionReport> ExecuteAsync(DetectOntCommand command, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var recommendations = new List<OperatorRecommendation>
        {
            OperatorRecommendation.ReadOnlyMode()
        };

        if (command.TrustLocalCertificate)
        {
            recommendations.Add(OperatorRecommendation.TrustLocalCertificate());
        }

        if (command.Adapter is { Ipv4: { } ipv4 } && !ipv4.IsInSameSubnet(command.TargetAddress))
        {
            var suggestion = SubnetSuggestion.ForTarget(command.TargetAddress);
            if (suggestion is not null)
            {
                recommendations.Add(OperatorRecommendation.SubnetMismatch(suggestion.ToOperatorText()));
            }
        }

        _probeSessionSettings.Trust = command.TrustLocalCertificate
            ? LocalCertificateTrust.ForSelectedEndpoint(command.TargetAddress)
            : LocalCertificateTrust.Denied(command.TargetAddress);

        var connectivity = await _probeService.ProbeAsync(
            new ProbeRequest(
                command.TargetAddress,
                command.Adapter,
                command.TrustLocalCertificate,
                TimeSpan.FromSeconds(3)),
            cancellationToken);

        DetectedDevice? device = null;
        DeviceCapabilities? capabilities = null;
        DeviceDiagnostics? diagnostics = null;
        var status = connectivity.AnyHttpReachable
            ? ApplicationStatus.Detected
            : connectivity.IcmpReachable
                ? ApplicationStatus.ControlledFailure
                : ApplicationStatus.ControlledFailure;

        if (connectivity.AnyHttpReachable)
        {
            var endpoint = connectivity.HttpsReachable
                ? OntEndpoint.Https(command.TargetAddress)
                : OntEndpoint.Http(command.TargetAddress);

            AdapterProbeResult? best = null;
            foreach (var adapter in _adapters)
            {
                var probe = await adapter.ProbeAsync(endpoint, cancellationToken);
                if (probe.Matched && (best is null || probe.Confidence > best.Confidence))
                {
                    best = probe;
                }
            }

            if (best is { Matched: true })
            {
                var session = AuthorizedDeviceSession.Public(best.Endpoint);
                var identityResult = await FindAdapter(best.AdapterId).ReadIdentityAsync(session, cancellationToken);
                var capabilityResult = await FindAdapter(best.AdapterId).ReadCapabilitiesAsync(session, cancellationToken);
                var diagnosticsResult = await FindAdapter(best.AdapterId).ReadDiagnosticsAsync(session, cancellationToken);

                var identity = identityResult.Identity ?? new DeviceIdentity(
                    best.Manufacturer,
                    best.Model,
                    FirmwareInfo.Unknown,
                    null,
                    null);

                device = new DetectedDevice(
                    best.Endpoint,
                    identity,
                    best.AdapterId,
                    best.Confidence,
                    best.Evidence.Select(item => $"{item.Source}: {item.Detail}").ToList(),
                    identityResult.RequiresAuthentication || diagnosticsResult.RequiresAuthentication);

                capabilities = capabilityResult.Capabilities;
                diagnostics = diagnosticsResult.Diagnostics;
                status = ApplicationStatus.Detected;

                if (_authAdapters.Any(item => item.CanAttemptAuthentication(best)))
                {
                    capabilities = capabilities is null
                        ? null
                        : capabilities with
                        {
                            AuthenticationMapped = true,
                            Notes = capabilities.Notes.Concat(
                            [
                                "Login homologado para F6201B V9.3.10P8N1: um POST no endpoint observado, leitura GET somente."
                            ]).ToList()
                        };
                    recommendations.Add(new OperatorRecommendation(
                        "AUTH",
                        "Autenticação homologada (somente leitura)",
                        "Informe a credencial da etiqueta e clique em Login uma vez. Nenhum outro POST será enviado.",
                        false));
                }
                else
                {
                    recommendations.Add(OperatorRecommendation.AuthenticationNotMapped());
                }
            }
            else
            {
                recommendations.Add(new OperatorRecommendation(
                    "EVIDENCE",
                    "Evidência insuficiente",
                    "O endereço respondeu, mas os marcadores públicos não identificaram um modelo homologado. Nenhuma suposição de fabricante foi aplicada.",
                    false));
                status = ApplicationStatus.ControlledFailure;
            }
        }
        else
        {
            var message = connectivity.ErrorMessage ?? "O alvo não respondeu em ICMP, HTTPS ou HTTP.";
            recommendations.Add(new OperatorRecommendation(
                "UNREACHABLE",
                "ONT não alcançada",
                message,
                true));
        }

        var report = new DetectionReport(
            command.Adapter,
            connectivity,
            device,
            capabilities,
            diagnostics,
            recommendations,
            status,
            DateTimeOffset.UtcNow - started,
            device is null
                ? DetectionConfidence.Insufficient
                : DetectionConfidenceDisplay.FromScore(device.Confidence, false),
            device?.Evidence,
            connectivity.PrimaryObservation);

        _auditLog.Record(AuditEvent.Create(
            "detect-ont",
            status.ToUiLabel(),
            command.TargetAddress.ToString(),
            $"https={connectivity.HttpsReachable}; http={connectivity.HttpReachable}; matched={(device is not null)}"));

        _logger.LogInformation(
            "Detecção concluída para {Target}: status={Status}, https={Https}, http={Http}",
            command.TargetAddress,
            status,
            connectivity.HttpsReachable,
            connectivity.HttpReachable);

        return report;
    }

    private IOntDeviceAdapter FindAdapter(string adapterId)
        => _adapters.First(item => item.AdapterId == adapterId);
}
