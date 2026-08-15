using System.IO.Compression;
using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Observation;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.Infrastructure.DependencyInjection;
using TantoOntManager.Infrastructure.Export;
using TantoOntManager.Infrastructure.Security;

namespace TantoOntManager.Application.Tests;

public sealed class WriteContractExportTests
{
    private const string Secret = "lab-pppoe-secret";

    [Fact]
    public async Task Export_redacts_secrets_keeps_configuration_sent_at_zero_and_blocks_before_network()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-write-" + Guid.NewGuid().ToString("N"));
        var engine = SeedWriteEngine();
        var observation = new ObservationSessionStore();
        observation.Attach(engine, Path.Combine(root, "webview"));
        var useCase = new ExportWriteContractUseCase(
            observation,
            new FakeAuthStore(),
            new LoggingPaths(root),
            NullLogger<ExportWriteContractUseCase>.Instance);

        var result = await useCase.ExecuteAsync(CancellationToken.None);
        result.IsSuccess.Should().BeTrue();
        result.Value!.Inspection.IsAcceptable.Should().BeTrue();
        result.Value.Inspection.ConfigurationRequestsSent.Should().Be(0);
        result.Value.Inspection.RequestBlockedBeforeNetwork.Should().BeTrue();
        result.Value.Inspection.IncludesCookies.Should().BeFalse();
        result.Value.Inspection.IncludesCredentials.Should().BeFalse();
        result.Value.Inspection.IncludesTokens.Should().BeFalse();
        result.Value.Inspection.IncludesRawRequestBody.Should().BeFalse();
        result.Value.Inspection.IncludesRawAuthenticatedHtml.Should().BeFalse();
        result.Value.Inspection.IncludesAuthorizationHeaders.Should().BeFalse();
        result.Value.Inspection.IncludesFullHeaders.Should().BeFalse();

        using var zip = ZipFile.OpenRead(result.Value.ZipPath);
        zip.Entries.Select(entry => entry.Name).Should().BeEquivalentTo(
            "write-contract-proposal.json",
            "write-contract-summary.txt",
            "blocked-request.json",
            "manifest.json");
        var combined = string.Join(Environment.NewLine, zip.Entries.Select(Read));
        combined.Should().NotContain(Secret);
        combined.Should().NotContain("SID_HTTPS_=");
        combined.Should().NotContain("_sessionTOKEN=");
        combined.Should().NotContain("Set-Cookie");
        combined.Should().NotContain("<html");
        combined.Should().Contain("\"ConfigurationRequestsSent\": 0");
        combined.Should().Contain("\"RequestBlockedBeforeNetwork\": true");
        combined.Should().Contain("CandidateOnly");
        Directory.Exists(result.Value.DirectoryPath).Should().BeTrue();
        File.ReadAllText(Path.Combine(result.Value.DirectoryPath, "manifest.json")).Should().Contain("IncludesRawRequestBody");
    }

    [Fact]
    public async Task Promote_does_not_change_adapter_and_write_allowlist_stays_empty()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-write-promote-" + Guid.NewGuid().ToString("N"));
        var adapter = RepoPath("src", "TantoOntManager.DeviceAdapters.Zte", "ZteDeviceAdapter.cs");
        var reader = RepoPath("src", "TantoOntManager.DeviceAdapters.Zte", "Auth", "F6201BAuthenticatedSafeReader.cs");
        var allowlist = RepoPath("src", "TantoOntManager.DeviceAdapters.Zte", "Auth", "F6201BV9310P8N1WriteAllowlist.cs");
        var beforeAdapter = File.ReadAllText(adapter);
        var beforeReader = File.ReadAllText(reader);
        var beforeAllowlist = File.ReadAllText(allowlist);
        var engine = SeedWriteEngineWithWriteUi();
        var observation = new ObservationSessionStore();
        observation.Attach(engine, Path.Combine(root, "webview"));
        var useCase = new PromoteWriteContractUseCase(
            observation,
            new LoggingPaths(root),
            NullLogger<PromoteWriteContractUseCase>.Instance);

        var result = await useCase.ExecuteAsync(CancellationToken.None);
        result.IsSuccess.Should().BeTrue();
        var payload = File.ReadAllText(result.Value!);
        payload.Should().Contain("CandidateOnly");
        payload.Should().Contain("\"NetworkRequestSent\": false");
        payload.Should().Contain("\"HumanReviewRequired\": true");
        payload.Should().Contain("\"BackupContractRequired\": true");
        payload.Should().Contain("\"RollbackContractRequired\": true");
        payload.Should().Contain("\"Phase2BRequired\": true");
        payload.Should().Contain("\"AdapterModified\": false");
        payload.Should().Contain("\"AllowlistModified\": false");
        payload.Should().Contain("\"WriteAllowlistEmpty\": true");
        payload.Should().NotContain(Secret);
        File.ReadAllText(adapter).Should().Be(beforeAdapter);
        File.ReadAllText(reader).Should().Be(beforeReader);
        File.ReadAllText(allowlist).Should().Be(beforeAllowlist);
        File.ReadAllText(allowlist).Should().Contain("Endpoints { get; } = [];");
        File.ReadAllText(allowlist).Should().Contain("=> false");
    }

    [Fact]
    public void Unsafe_export_is_refused_and_deleted()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-write-unsafe-" + Guid.NewGuid().ToString("N"));
        var directory = Path.Combine(root, "diagnostics", "proposals", "write-contract", "incomplete");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "write-contract-proposal.json"), "{\"Password\":\"" + Secret + "\",\"SID_HTTPS_\":\"abc\"}");
        File.WriteAllText(Path.Combine(directory, "write-contract-summary.txt"), "password=" + Secret);
        File.WriteAllText(Path.Combine(directory, "blocked-request.json"), "Cookie: SID_HTTPS_=abc");
        File.WriteAllText(Path.Combine(directory, "manifest.json"), "{\"ConfigurationRequestsSent\":0}");
        var zipPath = Path.Combine(root, "incomplete.zip");
        ZipFile.CreateFromDirectory(directory, zipPath);

        var result = WriteContractExportFinalizer.InspectAndKeepOrDelete(directory, zipPath);
        result.IsFailure.Should().BeTrue();
        result.Error!.Code.Should().Be(ErrorCodes.WriteCaptureExportInspectionFailed);
        Directory.Exists(directory).Should().BeFalse();
        File.Exists(zipPath).Should().BeFalse();
    }

    [Fact]
    public void Temporary_profile_is_destroyed_on_cancel()
    {
        var folder = Path.Combine(Path.GetTempPath(), "tanto-write-cancel-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "Cookies"), "SID_HTTPS_=secret");
        var store = new ObservationSessionStore();
        var engine = new ObservationEngine(IPAddress.Parse("192.168.100.1"));
        engine.StartBlockedWriteCapture(WriteCaptureEligibility.CompatibleLab("MAPEAR F6201B"));
        store.Attach(engine, folder);
        engine.CancelWriteCapture();
        store.FinishAndDestroy();
        Directory.Exists(folder).Should().BeFalse();
        store.TemporaryCookiesDestroyed.Should().BeTrue();
    }

    [Fact]
    public void Temporary_profile_is_destroyed_after_capture()
    {
        var folder = Path.Combine(Path.GetTempPath(), "tanto-write-captured-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "Cookies"), "SID_HTTPS_=secret");
        var store = new ObservationSessionStore();
        store.Attach(SeedWriteEngine(), folder);
        store.Engine!.WriteCandidate.Should().NotBeNull();
        store.FinishAndDestroy();
        Directory.Exists(folder).Should().BeFalse();
        store.LastSnapshot!.WriteCandidate.Should().NotBeNull();
        store.LastSnapshot.Counters.ConfigurationPostsSent.Should().Be(0);
        store.TemporaryCookiesDestroyed.Should().BeTrue();
    }

    [Fact]
    public void Observer_source_does_not_inject_javascript_or_click_automatically()
    {
        var source = File.ReadAllText(RepoPath("src", "TantoOntManager.App", "Observation", "ObservationWindow.xaml.cs"));
        source.Should().Contain("ExecuteScriptAsync(WriteCapabilityDomScript.Source)");
        source.Should().NotContain("AddScriptToExecuteOnDocumentCreated");
        source.Should().NotContain("InvokeScript");
        source.Should().NotContain("Click()");
        source.Should().NotContain("PerformClick");
        source.Should().Contain("CreateWebResourceResponse");
        source.Should().Contain("args.Response = CreateBlockedResponse()");
        source.Should().Contain("WriteCapabilityDomScript.IsSafe()");
        (source.Split("ExecuteScriptAsync").Length - 1).Should().Be(1);
    }

    private static ObservationEngine SeedWriteEngine()
    {
        var engine = new ObservationEngine(IPAddress.Parse("192.168.100.1"));
        engine.StartBlockedWriteCapture(WriteCaptureEligibility.CompatibleLab("MAPEAR F6201B")).IsSuccess.Should().BeTrue();
        engine.Evaluate(new IncomingObservationRequest("GET", new Uri("https://192.168.100.1/?_type=menuView&_tag=ethWanConfig")));
        var payload = WriteBodyInspector.ToPayload(
            "application/x-www-form-urlencoded",
            "VlanEnable=1&VLANID=210&Password=" + Secret + "&MTU=1500&Apply=1",
            "https://192.168.100.1/?_type=menuView&_tag=ethWanConfig",
            "xhr",
            "Apply");
        engine.Evaluate(
            new IncomingObservationRequest("POST", new Uri("https://192.168.100.1/?_type=menuData&_tag=wanSave")),
            payload);
        return engine;
    }

    private static ObservationEngine SeedWriteEngineWithWriteUi()
    {
        var engine = SeedWriteEngine();
        engine.SetCapabilityContext(new WriteCapabilityContext(
            "ZTE",
            "F6201B",
            FirmwareCompatibility.ConfirmedCompatible,
            "V9.3.10P8N1",
            "admin",
            ["HSI_TR069", "VOIP_IPTV"]));
        engine.StartScreenCapture(ObservationScreen.WanConfig);
        engine.IngestDomSnapshot(new WriteCapabilityDomSnapshot(
            ["Internet", "WAN"],
            [
                new ObservedDomControl("SELECT", "IPType", "ipType", "select-one", false, false, false, ["DHCP", "Static", "PPPoE"], null, null, false),
                new ObservedDomControl("BUTTON", "btnApply", "Apply", "submit", false, false, false, [], "Apply", "onApply", false)
            ],
            true));
        return engine;
    }

    private static string RepoPath(params string[] parts)
        => Path.GetFullPath(Path.Combine(new[] { AppContext.BaseDirectory, "..", "..", "..", "..", ".." }.Concat(parts).ToArray()));

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
