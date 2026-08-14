using System.IO.Compression;
using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Observation;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.Infrastructure.DependencyInjection;
using TantoOntManager.Infrastructure.Export;
using TantoOntManager.Infrastructure.Security;

namespace TantoOntManager.Application.Tests;

public sealed class ObservationExportAndPromoteTests
{
    [Fact]
    public async Task Zip_has_no_raw_authenticated_bodies_cookies_or_tokens()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-obs-" + Guid.NewGuid().ToString("N"));
        var engine = SeedEngine();
        var observation = new ObservationSessionStore();
        observation.Attach(engine, Path.Combine(root, "webview"));
        var auth = new FakeAuthStore();
        var useCase = new ExportObservationUseCase(observation, auth, new LoggingPaths(root), NullLogger<ExportObservationUseCase>.Instance);

        var result = await useCase.ExecuteAsync(CancellationToken.None);
        result.IsSuccess.Should().BeTrue();
        result.Value!.Inspection.IsAcceptable.Should().BeTrue();
        result.Value.Inspection.IncludesCookies.Should().BeFalse();
        result.Value.Inspection.IncludesCredentials.Should().BeFalse();
        result.Value.Inspection.IncludesTokens.Should().BeFalse();
        result.Value.Inspection.IncludesRawAuthenticatedBody.Should().BeFalse();
        result.Value.Inspection.SensitiveIdentifiersMasked.Should().BeTrue();
        result.Value.Inspection.ConfigurationRequestsSent.Should().Be(0);

        using var zip = ZipFile.OpenRead(result.Value.ZipPath);
        zip.Entries.Select(entry => entry.Name).Should().BeEquivalentTo(
            "observation-summary.txt",
            "observed-get-contracts.json",
            "response-structures.json",
            "blocked-requests.json",
            "manifest.json");
        var combined = string.Join(Environment.NewLine, zip.Entries.Select(Read));
        combined.Should().NotContain("<html");
        combined.Should().NotContain("SID_HTTPS_=");
        combined.Should().NotContain("_sessionTOKEN=");
        combined.Should().NotContain("lab-pass");
        combined.Should().NotContain("AA:BB:CC:DD:EE:FF");
    }

    [Fact]
    public async Task Promote_writes_local_proposal_without_changing_adapter()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-obs-promote-" + Guid.NewGuid().ToString("N"));
        var adapter = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "TantoOntManager.DeviceAdapters.Zte", "ZteDeviceAdapter.cs"));
        var before = File.ReadAllText(adapter);
        var engine = SeedEngine();
        var observation = new ObservationSessionStore();
        observation.Attach(engine, Path.Combine(root, "webview"));
        var auth = new FakeAuthStore
        {
            Snapshot = new AuthenticatedReadSnapshot(
                new DeviceIdentity(ManufacturerNames.Zte, DeviceModelIds.ZteF6201B, FirmwareInfo.Unknown, null, null),
                DeviceDiagnostics.PublicInterfaceOnly("teste"),
                ["/"],
                1,
                0,
                "200",
                "hash",
                TimeSpan.Zero,
                "zte",
                [],
                [],
                1,
                0,
                0)
            {
                FirmwareCompatibility = FirmwareCompatibility.Unconfirmed
            }
        };
        var useCase = new PromoteReadContractUseCase(observation, auth, new LoggingPaths(root), NullLogger<PromoteReadContractUseCase>.Instance);
        var result = await useCase.ExecuteAsync(CancellationToken.None);
        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Contain("proposals");
        File.Exists(result.Value!).Should().BeTrue();
        File.ReadAllText(result.Value!).Should().Contain("WriteForbidden");
        File.ReadAllText(result.Value!).Should().Contain("Unconfirmed");
        File.ReadAllText(adapter).Should().Be(before);
        Directory.GetFiles(Path.GetDirectoryName(adapter)!, "*.cs").Should().NotContain(result.Value);
    }

    [Fact]
    public void Closing_observer_destroys_temporary_cookies_folder()
    {
        var folder = Path.Combine(Path.GetTempPath(), "tanto-obs-close-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "Cookies"), "SID_HTTPS_=secret");
        var store = new ObservationSessionStore();
        store.Attach(new ObservationEngine(IPAddress.Parse("192.168.100.1")), folder);
        store.TemporaryCookiesDestroyed.Should().BeFalse();
        store.FinishAndDestroy();
        store.TemporaryCookiesDestroyed.Should().BeTrue();
        Directory.Exists(folder).Should().BeFalse();
        store.IsOpen.Should().BeFalse();
    }

    [Fact]
    public void Failed_createasync_cleanup_destroys_empty_folder_and_is_idempotent()
    {
        var folder = Path.Combine(Path.GetTempPath(), "observer-webview", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var store = new ObservationSessionStore();
        store.Attach(new ObservationEngine(IPAddress.Parse("192.168.100.1")), folder);
        store.FinishAndDestroy();
        store.FinishAndDestroy();
        Directory.Exists(folder).Should().BeFalse();
        store.IsOpen.Should().BeFalse();
        store.TemporaryCookiesDestroyed.Should().BeTrue();
        store.Engine.Should().BeNull();
    }

    [Fact]
    public void No_configuration_post_is_recorded_in_snapshot()
    {
        var engine = SeedEngine();
        engine.Evaluate(new IncomingObservationRequest("POST", new Uri("https://192.168.100.1/?_tag=wanSave")));
        engine.Snapshot().Counters.ConfigurationPostsSent.Should().Be(0);
        engine.Snapshot().Counters.PostsObservedAndBlocked.Should().BeGreaterThan(0);
    }

    private static ObservationEngine SeedEngine()
    {
        var engine = new ObservationEngine(IPAddress.Parse("192.168.100.1"));
        var shell = new Uri("https://192.168.100.1/");
        engine.Evaluate(new IncomingObservationRequest("GET", shell));
        engine.CompleteGet(new IncomingObservationRequest("GET", shell), 200, "text/html", "<div>shell</div>", null);
        engine.CloseBaseline();
        engine.StartScreenCapture(ObservationScreen.Device);
        var data = new Uri("https://192.168.100.1/?_type=menuData&_tag=devBasicStatus");
        engine.Evaluate(new IncomingObservationRequest("GET", data));
        engine.CompleteGet(
            new IncomingObservationRequest("GET", data),
            200,
            "application/json",
            """{"SoftwareVersion":"V9.3.10P8N1","MACAddress":"AA:BB:CC:DD:EE:FF"}""",
            null);
        return engine;
    }

    private static string Read(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private sealed class FakeAuthStore : IOntAuthSessionStore
    {
        public AuthorizedDeviceSession? DomainSession { get; set; } = AuthorizedDeviceSession.Authenticated(
            OntEndpoint.Https(IPAddress.Parse("192.168.100.1")),
            "zte-f6201b-v9.3.10p8n1-json-login",
            "abc");
        public IBoundOntTransport? Transport { get; set; }
        public AuthenticatedReadSnapshot? Snapshot { get; set; }
        public AuthenticatedReadMap? ReadMap { get; set; }
        public AuthSessionState State { get; set; } = AuthSessionState.AuthenticatedReadOnly;
        public void Remember(IBoundOntTransport transport, AuthorizedDeviceSession session, AuthenticatedReadSnapshot snapshot) { }
        public void RememberReadMap(AuthenticatedReadMap map) => ReadMap = map;
        public void ReplaceSnapshot(AuthenticatedReadSnapshot snapshot) => Snapshot = snapshot;
        public void End(string reason) { }
        public void SetState(AuthSessionState state) => State = state;
        public bool IsBoundTo(IPAddress address, string? certificateSha256) => true;
    }
}
