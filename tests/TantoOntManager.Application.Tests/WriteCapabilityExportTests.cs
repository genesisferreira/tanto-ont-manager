using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Observation;
using TantoOntManager.Infrastructure.DependencyInjection;
using TantoOntManager.Infrastructure.Export;
using TantoOntManager.Infrastructure.Security;

namespace TantoOntManager.Application.Tests;

public sealed class WriteCapabilityExportTests
{
    [Fact]
    public async Task Export_has_no_cookies_tokens_passwords_or_raw_html()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-capability-" + Guid.NewGuid().ToString("N"));
        var engine = LabEngineWithoutPppoe();
        var observation = new ObservationSessionStore();
        observation.Attach(engine, Path.Combine(root, "webview"));
        var useCase = new ExportWriteCapabilityUseCase(
            observation,
            new LoggingPaths(root),
            NullLogger<ExportWriteCapabilityUseCase>.Instance);

        var result = await useCase.ExecuteAsync(CancellationToken.None);
        result.IsSuccess.Should().BeTrue();
        result.Value!.Inspection.IsAcceptable.Should().BeTrue();
        result.Value.Inspection.IncludesCookies.Should().BeFalse();
        result.Value.Inspection.IncludesCredentials.Should().BeFalse();
        result.Value.Inspection.IncludesTokens.Should().BeFalse();
        result.Value.Inspection.IncludesRawAuthenticatedHtml.Should().BeFalse();
        result.Value.Inspection.ConfigurationRequestsSent.Should().Be(0);

        var directory = result.Value.DirectoryPath;
        Directory.GetFiles(directory).Select(Path.GetFileName).Should().BeEquivalentTo(
            "write-capability-report.json",
            "write-capability-summary.txt",
            "manifest.json");
        var combined = string.Join(Environment.NewLine, Directory.GetFiles(directory).Select(File.ReadAllText));
        combined.Should().NotContain("SID_HTTPS_=");
        combined.Should().NotContain("_sessionTOKEN=");
        combined.Should().NotContain("Set-Cookie");
        combined.Should().NotContain("<html");
        combined.Should().NotContain("</html>");
        combined.Should().NotContain("password=");
        combined.Should().NotContain("Password=");
        combined.Should().NotContain("Authorization:");
        combined.Should().Contain("\"ConfigurationRequestsSent\": 0");
        combined.Should().Contain("PppoeOptionUnavailable");
        combined.Should().Contain(WriteCapabilityReport.PppoeUnavailableOperatorMessage);
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
    }

    [Fact]
    public async Task Promote_is_blocked_with_zero_candidates()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-capability-zero-" + Guid.NewGuid().ToString("N"));
        var engine = new ObservationEngine(IPAddress.Parse("192.168.100.1"));
        engine.SetCapabilityContext(LabContext());
        engine.StartScreenCapture(ObservationScreen.WanConfig);
        engine.IngestDomSnapshot(WriteUiAvailable());
        var observation = new ObservationSessionStore();
        observation.Attach(engine, Path.Combine(root, "webview"));
        var useCase = new PromoteWriteContractUseCase(
            observation,
            new LoggingPaths(root),
            NullLogger<PromoteWriteContractUseCase>.Instance);

        var result = await useCase.ExecuteAsync(CancellationToken.None);
        result.IsFailure.Should().BeTrue();
        result.Error!.Code.Should().Be(ErrorCodes.WritePromotionBlocked);
        result.Error.Message.Should().Contain("candidatos interceptados = 0");
        Directory.Exists(Path.Combine(root, "diagnostics", "proposals", "write-contract")).Should().BeFalse();
    }

    [Fact]
    public async Task Promote_is_blocked_without_pppoe()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-capability-nopppoe-" + Guid.NewGuid().ToString("N"));
        var engine = LabEngineWithoutPppoe();
        engine.StartBlockedWriteCapture(WriteCaptureEligibility.CompatibleLab("MAPEAR F6201B")).IsSuccess.Should().BeTrue();
        engine.Evaluate(
            new IncomingObservationRequest("POST", new Uri("https://192.168.100.1/?_type=menuData&_tag=wanSave")),
            WriteBodyInspector.ToPayload(
                "application/x-www-form-urlencoded",
                "VlanEnable=1&VLANID=210&MTU=1500&Apply=1",
                "https://192.168.100.1/?_type=menuView&_tag=ethWanConfig",
                "xhr",
                "Apply"));
        var observation = new ObservationSessionStore();
        observation.Attach(engine, Path.Combine(root, "webview"));
        var useCase = new PromoteWriteContractUseCase(
            observation,
            new LoggingPaths(root),
            NullLogger<PromoteWriteContractUseCase>.Instance);

        var result = await useCase.ExecuteAsync(CancellationToken.None);
        result.IsFailure.Should().BeTrue();
        result.Error!.Code.Should().Be(ErrorCodes.WritePromotionBlocked);
        result.Error.Message.Should().Contain("PPPoE");
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
        engine.WriteCapability.Conclusion.Should().Be(WriteCapabilityConclusion.PppoeOptionUnavailable);
    }

    private static ObservationEngine LabEngineWithoutPppoe()
    {
        var engine = new ObservationEngine(IPAddress.Parse("192.168.100.1"));
        engine.SetCapabilityContext(LabContext());
        engine.StartScreenCapture(ObservationScreen.WanConfig);
        engine.IngestDomSnapshot(new WriteCapabilityDomSnapshot(
            ["Internet", "WAN", "Status"],
            [
                new ObservedDomControl("SELECT", "IPType", "ipType", "select-one", false, false, false, ["DHCP", "Static"], null, null, false)
            ],
            true));
        return engine;
    }

    private static WriteCapabilityContext LabContext()
        => new(
            "ZTE",
            "F6201B",
            FirmwareCompatibility.ConfirmedCompatible,
            "V9.3.10P8N1",
            "admin",
            ["HSI_TR069", "VOIP_IPTV"]);

    private static WriteCapabilityDomSnapshot WriteUiAvailable()
        => new(
            ["Internet", "WAN"],
            [
                new ObservedDomControl("SELECT", "IPType", "ipType", "select-one", false, false, false, ["DHCP", "Static", "PPPoE"], null, null, false),
                new ObservedDomControl("BUTTON", "btnApply", "Apply", "submit", false, false, false, [], "Apply", "onApply", false)
            ],
            true);
}
