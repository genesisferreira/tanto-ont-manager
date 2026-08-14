using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Network;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Application.UseCases;

public sealed class TestConnectionUseCase : ITestConnectionUseCase
{
    private readonly IConnectivityProbeService _probeService;
    private readonly IAuditLogService _auditLog;
    private readonly ProbeSessionSettings _probeSessionSettings;
    private readonly ILogger<TestConnectionUseCase> _logger;

    public TestConnectionUseCase(
        IConnectivityProbeService probeService,
        IAuditLogService auditLog,
        ProbeSessionSettings probeSessionSettings,
        ILogger<TestConnectionUseCase> logger)
    {
        _probeService = probeService;
        _auditLog = auditLog;
        _probeSessionSettings = probeSessionSettings;
        _logger = logger;
    }

    public async Task<ConnectivityProbeResult> ExecuteAsync(
        TestConnectionCommand command,
        CancellationToken cancellationToken)
    {
        _probeSessionSettings.Trust = command.TrustLocalCertificate
            ? LocalCertificateTrust.ForSelectedEndpoint(command.TargetAddress)
            : LocalCertificateTrust.Denied(command.TargetAddress);

        var result = await _probeService.ProbeAsync(
            new ProbeRequest(
                command.TargetAddress,
                command.Adapter,
                command.TrustLocalCertificate,
                TimeSpan.FromSeconds(3)),
            cancellationToken);

        _auditLog.Record(AuditEvent.Create(
            "test-connection",
            result.AnyHttpReachable ? "alcançado" : "não alcançado",
            command.TargetAddress.ToString(),
            $"icmp={result.IcmpReachable}; https={result.HttpsReachable}; http={result.HttpReachable}"));

        _logger.LogInformation(
            "Teste de conexão em {Target}: icmp={Icmp} https={Https} http={Http}",
            command.TargetAddress,
            result.IcmpReachable,
            result.HttpsReachable,
            result.HttpReachable);

        return result;
    }
}

public sealed class ListEthernetAdaptersUseCase : IListEthernetAdaptersUseCase
{
    private readonly IEthernetDiscoveryService _discovery;

    public ListEthernetAdaptersUseCase(IEthernetDiscoveryService discovery)
    {
        _discovery = discovery;
    }

    public IReadOnlyList<EthernetAdapterInfo> Execute() => _discovery.ListEthernetAdapters();
}
