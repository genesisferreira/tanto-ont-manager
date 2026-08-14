using System.IO.Compression;
using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.Infrastructure.DependencyInjection;
using TantoOntManager.Infrastructure.Export;
using TantoOntManager.Security.Export;

namespace TantoOntManager.Application.Tests;

public sealed class ExportAuthenticatedDiagnosticTests
{
    [Fact]
    public async Task Export_masks_serial_mac_and_omits_html()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-auth-export-" + Guid.NewGuid().ToString("N"));
        var store = new FakeStore
        {
            DomainSession = AuthorizedDeviceSession.Authenticated(
                OntEndpoint.Https(IPAddress.Parse("192.168.100.1")),
                "zte-f6201b-v9.3.10p8n1-json-login",
                "abc"),
            Snapshot = new AuthenticatedReadSnapshot(
                new DeviceIdentity(
                    ManufacturerNames.Zte,
                    DeviceModelIds.ZteF6201B,
                    new FirmwareInfo("V9.3.10P8N1", "V9.3.12", "V9.3.10P10N6"),
                    "ABCDEF123456",
                    "AABBCCDDEEFF"),
                new DeviceDiagnostics(
                    new PonState("O1", null),
                    new OpticalReading("41", "2.1", "-18", "3.3", "12"),
                    [new WanProfile("HSI_TR069", "PPPoE", "INTERNET", null, null, null, null, 210, null, "Disconnected", null, "100.64.x.x")],
                    null,
                    false,
                    "ok"),
                ["/", "/?_type=menuView&_tag=devinfo"],
                1,
                0,
                "200",
                "abcd1234",
                TimeSpan.FromMilliseconds(50),
                "zte-f6201b-v9.3.10p8n1-auth-v1",
                [],
                [],
                1,
                0,
                0)
        };

        var useCase = new ExportAuthenticatedDiagnosticUseCase(
            store,
            new LoggingPaths(root),
            new SilentAudit(),
            NullLogger<ExportAuthenticatedDiagnosticUseCase>.Instance);

        var result = await useCase.ExecuteAsync(new ExportAuthenticatedDiagnosticCommand("lab-user", "lab-pass"), CancellationToken.None);
        result.IsSuccess.Should().BeTrue();

        using var zip = ZipFile.OpenRead(result.Value!.ZipPath);
        zip.Entries.Select(entry => entry.Name).Should().BeEquivalentTo(
            "manifest.json",
            "device-information.json",
            "pon-status.json",
            "wan-summary.json",
            "safe-read-inventory.json",
            "authenticated-diagnostic-summary.txt");

        var combined = string.Join(Environment.NewLine, zip.Entries.Select(Read));
        combined.Should().NotContain("ABCDEF123456");
        combined.Should().NotContain("AABBCCDDEEFF");
        combined.Should().NotContain("lab-pass");
        combined.Should().NotContain("<html");
        combined.Should().NotContain("Set-Cookie");
        combined.Should().NotContain("pppoeuser");
        combined.Should().Contain("ABC******456");

        result.Value!.Inspection.IncludesCookies.Should().BeFalse();
        result.Value.Inspection.IncludesCredentials.Should().BeFalse();
        result.Value.Inspection.IncludesRawAuthenticatedHtml.Should().BeFalse();
        result.Value.Inspection.SensitiveIdentifiersMasked.Should().BeTrue();
    }

    [Fact]
    public async Task Export_is_blocked_without_session()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-auth-export-" + Guid.NewGuid().ToString("N"));
        var useCase = new ExportAuthenticatedDiagnosticUseCase(
            new FakeStore(),
            new LoggingPaths(root),
            new SilentAudit(),
            NullLogger<ExportAuthenticatedDiagnosticUseCase>.Instance);

        var result = await useCase.ExecuteAsync(new ExportAuthenticatedDiagnosticCommand(null, null), CancellationToken.None);
        result.IsFailure.Should().BeTrue();
        result.Error!.Code.Should().Be(ErrorCodes.AuthenticatedExportRequiresSession);
    }

    [Fact]
    public void Sanitizer_redacts_secrets_from_logs()
    {
        var text = AuthenticatedPayloadSanitizer.Sanitize("password=lab-pass token=deadbeef");
        text.Should().NotContain("lab-pass");
        text.Should().NotContain("deadbeef");
        text.Should().Contain("[redacted]");
        AuthenticatedPayloadSanitizer.Sanitize("wan=8.8.8.8").Should().Contain("8.8.x.x");
        AuthenticatedPayloadSanitizer.LooksUnsanitized("Set-Cookie: a=b").Should().BeTrue();
    }

    private static string Read(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private sealed class FakeStore : IOntAuthSessionStore
    {
        public AuthorizedDeviceSession? DomainSession { get; set; }
        public IBoundOntTransport? Transport { get; set; }
        public AuthenticatedReadSnapshot? Snapshot { get; set; }
        public AuthSessionState State { get; set; } = AuthSessionState.Unmapped;
        public void Remember(IBoundOntTransport transport, AuthorizedDeviceSession session, AuthenticatedReadSnapshot snapshot) { }
        public void End(string reason) { }
        public void SetState(AuthSessionState state) => State = state;
        public bool IsBoundTo(IPAddress address, string? certificateSha256) => false;
    }

    private sealed class SilentAudit : IAuditLogService
    {
        public void Record(AuditEvent auditEvent)
        {
        }
    }
}
