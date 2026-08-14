using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Application.UseCases;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Application.Tests;

public sealed class DetectOntUseCaseTests
{
    [Fact]
    public async Task Reports_subnet_mismatch_without_changing_adapter()
    {
        var adapter = new EthernetAdapterInfo(
            "nic",
            "Ethernet",
            "Test NIC",
            true,
            new Ipv4Configuration(IPAddress.Parse("192.168.0.10"), IPAddress.Parse("255.255.255.0")),
            "Up");

        var probe = new FakeProbeService
        {
            Result = new ConnectivityProbeResult(
                OntEndpoint.Https(IPAddress.Parse("192.168.100.1")),
                false,
                false,
                false,
                null,
                null,
                null,
                null,
                null,
                null,
                TimeSpan.FromMilliseconds(10),
                "sem resposta")
        };

        var useCase = new DetectOntUseCase(
            probe,
            Array.Empty<IOntDeviceAdapter>(),
            Array.Empty<IOntAuthenticationAdapter>(),
            new FakeAudit(),
            new ProbeSessionSettings(),
            NullLogger<DetectOntUseCase>.Instance);

        var report = await useCase.ExecuteAsync(
            new DetectOntCommand(adapter, IPAddress.Parse("192.168.100.1"), true),
            CancellationToken.None);

        report.Recommendations.Should().Contain(item => item.Code == "SUBNET");
        report.Recommendations.Should().Contain(item => item.Code == "RO");
        report.Device.Should().BeNull();
    }

    [Fact]
    public async Task Identifies_device_when_adapter_matches_public_evidence()
    {
        var endpoint = OntEndpoint.Https(IPAddress.Parse("192.168.100.1"));
        var probe = new FakeProbeService
        {
            Result = new ConnectivityProbeResult(
                endpoint,
                true,
                true,
                false,
                200,
                null,
                "ZXHN F6201B",
                null,
                "<title>ZXHN F6201B</title>",
                "certificado local",
                TimeSpan.FromMilliseconds(20),
                null)
        };

        var deviceAdapter = new FakeZteAdapter();
        var useCase = new DetectOntUseCase(
            probe,
            new[] { deviceAdapter },
            Array.Empty<IOntAuthenticationAdapter>(),
            new FakeAudit(),
            new ProbeSessionSettings(),
            NullLogger<DetectOntUseCase>.Instance);

        var report = await useCase.ExecuteAsync(
            new DetectOntCommand(null, IPAddress.Parse("192.168.100.1"), true),
            CancellationToken.None);

        report.Device.Should().NotBeNull();
        report.Device!.Identity.Model.Should().Be(DeviceModelIds.ZteF6201B);
        report.Status.Should().Be(ApplicationStatus.Detected);
        report.Capabilities!.WriteOperationsSupportedByAdapter.Should().BeFalse();
        report.Capabilities.AuthenticationMapped.Should().BeFalse();
    }

    private sealed class FakeProbeService : IConnectivityProbeService
    {
        public ConnectivityProbeResult Result { get; set; } = null!;

        public Task<ConnectivityProbeResult> ProbeAsync(ProbeRequest request, CancellationToken cancellationToken)
            => Task.FromResult(Result);
    }

    private sealed class FakeAudit : IAuditLogService
    {
        public void Record(AuditEvent auditEvent)
        {
        }
    }

    private sealed class FakeZteAdapter : IOntDeviceAdapter
    {
        public string AdapterId => "zte-zxhn-public-v1";
        public string Manufacturer => ManufacturerNames.Zte;
        public IReadOnlyCollection<string> SupportedModels { get; } = [DeviceModelIds.ZteF6201B];

        public Task<AdapterProbeResult> ProbeAsync(OntEndpoint endpoint, CancellationToken cancellationToken)
            => Task.FromResult(AdapterProbeResult.Match(
                AdapterId,
                Manufacturer,
                DeviceModelIds.ZteF6201B,
                0.93,
                endpoint,
                [new ProbeEvidence("title", "ZXHN F6201B")],
                true,
                true));

        public Task<DeviceIdentityResult> ReadIdentityAsync(AuthorizedDeviceSession session, CancellationToken cancellationToken)
            => Task.FromResult(DeviceIdentityResult.Success(
                new DeviceIdentity(Manufacturer, DeviceModelIds.ZteF6201B, FirmwareInfo.Unknown, null, null)) with
            {
                RequiresAuthentication = true
            });

        public Task<DeviceDiagnosticsResult> ReadDiagnosticsAsync(AuthorizedDeviceSession session, CancellationToken cancellationToken)
            => Task.FromResult(DeviceDiagnosticsResult.Success(DeviceDiagnostics.PublicInterfaceOnly("somente público")));

        public Task<DeviceCapabilitiesResult> ReadCapabilitiesAsync(AuthorizedDeviceSession session, CancellationToken cancellationToken)
            => Task.FromResult(DeviceCapabilitiesResult.Success(new DeviceCapabilities(
                true, true, false, true, false, true, false, false, ["somente leitura"])));
    }
}

public sealed class AuthenticateDeviceUseCaseTests
{
    [Fact]
    public async Task Does_not_send_credentials_when_method_is_not_mapped()
    {
        var store = new TrackingStore();
        var useCase = new AuthenticateDeviceUseCase(
            Array.Empty<IOntAuthenticationAdapter>(),
            store,
            new SilentAudit(),
            new ProbeSessionSettings(),
            NullLogger<AuthenticateDeviceUseCase>.Instance);

        using var password = new System.Security.SecureString();
        password.AppendChar('x');
        using var credentials = new DeviceCredentials("user", password.Copy(), false);

        var probe = AdapterProbeResult.Match(
            "zte-zxhn-public-v1",
            ManufacturerNames.Zte,
            DeviceModelIds.ZteF6201B,
            0.9,
            OntEndpoint.Https(IPAddress.Parse("192.168.100.1")),
            [],
            true,
            true);

        var result = await useCase.ExecuteAsync(
            new AuthenticateCommand(probe.Endpoint, probe, credentials),
            CancellationToken.None);

        result.Outcome.Should().Be(AuthenticationOutcome.MethodNotMapped);
        result.Error!.Code.Should().Be(ErrorCodes.AuthenticationMethodNotMapped);
        store.Forgotten.Should().BeTrue();
    }

    private sealed class TrackingStore : ISecureCredentialStore
    {
        public bool PersistenceEnabled => false;
        public bool Forgotten { get; private set; }
        public void Forget(DeviceCredentials credentials) => Forgotten = true;
    }

    private sealed class SilentAudit : IAuditLogService
    {
        public void Record(AuditEvent auditEvent)
        {
        }
    }
}
