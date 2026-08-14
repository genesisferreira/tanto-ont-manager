using System.IO.Compression;
using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.Infrastructure.DependencyInjection;
using TantoOntManager.Infrastructure.Export;

namespace TantoOntManager.Application.Tests;

public sealed class ExportAuthenticatedReadMapTests
{
    [Fact]
    public async Task Export_contains_only_sanitized_map_files()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-read-map-" + Guid.NewGuid().ToString("N"));
        var store = new FakeStore
        {
            DomainSession = AuthorizedDeviceSession.Authenticated(
                OntEndpoint.Https(IPAddress.Parse("192.168.100.1")),
                "zte-f6201b-v9.3.10p8n1-json-login",
                "abc"),
            ReadMap = new AuthenticatedReadMap(
                [
                    new AuthenticatedReadMapEntry(
                        "Internet → PON Information",
                        "menuView",
                        "ponInfo",
                        "menuTreeJSON:page@/",
                        SafeReadClassification.SafeRead,
                        "Referenciada explicitamente",
                        200,
                        "text/html",
                        120,
                        "abcd1234",
                        true,
                        true)
                ],
                ["menuData+_tag concatenado com variável; tag não inventada"],
                ["Internet → PON Information"],
                ["Management & Diagnosis → Status"],
                1,
                0,
                0,
                "Nenhum endpoint foi adivinhado.")
        };

        var useCase = new ExportAuthenticatedReadMapUseCase(
            store,
            new LoggingPaths(root),
            new SilentAudit(),
            NullLogger<ExportAuthenticatedReadMapUseCase>.Instance);

        var result = await useCase.ExecuteAsync(CancellationToken.None);
        result.IsSuccess.Should().BeTrue();
        using var zip = ZipFile.OpenRead(result.Value!.ZipPath);
        zip.Entries.Select(entry => entry.Name).Should().BeEquivalentTo(
            "authenticated-read-map.json",
            "authenticated-read-map.txt");
        var combined = string.Join(Environment.NewLine, zip.Entries.Select(Read));
        combined.Should().Contain("ponInfo");
        combined.Should().NotContain("<html");
        combined.Should().NotContain("Set-Cookie");
        combined.Should().NotContain("SID_HTTPS_=");
        combined.Should().NotContain("_sessionTOKEN=");
        combined.Should().Contain("Kind");
        result.Value.Inspection.IncludesRawAuthenticatedHtml.Should().BeFalse();
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
        public Domain.Sessions.AuthenticatedReadSnapshot? Snapshot { get; set; }
        public AuthenticatedReadMap? ReadMap { get; set; }
        public AuthSessionState State { get; set; } = AuthSessionState.AuthenticatedReadOnly;
        public void Remember(IBoundOntTransport transport, AuthorizedDeviceSession session, Domain.Sessions.AuthenticatedReadSnapshot snapshot) { }
        public void RememberReadMap(AuthenticatedReadMap map) => ReadMap = map;
        public void ReplaceSnapshot(Domain.Sessions.AuthenticatedReadSnapshot snapshot) => Snapshot = snapshot;
        public void End(string reason) { }
        public void SetState(AuthSessionState state) => State = state;
        public bool IsBoundTo(IPAddress address, string? certificateSha256) => true;
    }

    private sealed class SilentAudit : IAuditLogService
    {
        public void Record(AuditEvent auditEvent)
        {
        }
    }
}
