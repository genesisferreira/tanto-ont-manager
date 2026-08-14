using System.Net;
using FluentAssertions;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.Domain.Tests;

public sealed class ObservationRequestGateTests
{
    private static readonly IPAddress Ont = IPAddress.Parse("192.168.100.1");

    [Fact]
    public void Allows_get_to_bound_ip()
    {
        var decision = ObservationRequestGate.Evaluate(
            new IncomingObservationRequest("GET", new Uri("https://192.168.100.1/?_type=menuData&_tag=ethWanStatus")),
            Ont,
            cancelled: false);
        decision.Allowed.Should().BeTrue();
    }

    [Fact]
    public void Blocks_get_to_other_ip()
    {
        var decision = ObservationRequestGate.Evaluate(
            new IncomingObservationRequest("GET", new Uri("https://192.168.1.1/")),
            Ont,
            cancelled: false);
        decision.Allowed.Should().BeFalse();
        decision.EndsObservation.Should().BeTrue();
    }

    [Fact]
    public void Blocks_external_redirect()
    {
        var decision = ObservationRequestGate.Evaluate(
            new IncomingObservationRequest(
                "GET",
                new Uri("https://192.168.100.1/"),
                RedirectLocation: new Uri("https://example.com/")),
            Ont,
            cancelled: false);
        decision.Allowed.Should().BeFalse();
        decision.Reason.Should().Contain("Redirect");
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public void Blocks_mutating_methods(string method)
    {
        var decision = ObservationRequestGate.Evaluate(
            new IncomingObservationRequest(method, new Uri("https://192.168.100.1/")),
            Ont,
            cancelled: false);
        decision.Allowed.Should().BeFalse();
    }

    [Theory]
    [InlineData("wan_apply")]
    [InlineData("wanSave")]
    [InlineData("wanCreate")]
    [InlineData("wanDelete")]
    [InlineData("wanModify")]
    public void Blocks_action_tokens_even_on_get(string tag)
    {
        var decision = ObservationRequestGate.Evaluate(
            new IncomingObservationRequest("GET", new Uri("https://192.168.100.1/?_type=menuView&_tag=" + tag)),
            Ont,
            cancelled: false);
        decision.Allowed.Should().BeFalse();
        decision.Reason.Should().Contain("ação");
    }

    [Fact]
    public void Allows_head_on_bound_ip()
    {
        ObservationRequestGate.Evaluate(
            new IncomingObservationRequest("HEAD", new Uri("https://192.168.100.1/jquery/common.js")),
            Ont,
            cancelled: false).Allowed.Should().BeTrue();
    }
}

public sealed class ObservationEngineTests
{
    private static readonly IPAddress Ont = IPAddress.Parse("192.168.100.1");

    [Fact]
    public void Baseline_is_separated_from_new_gets()
    {
        using var engine = new ObservationEngine(Ont);
        AllowGet(engine, "https://192.168.100.1/style.css", "<css>a</css>", "text/css");
        engine.CloseBaseline();
        engine.StartScreenCapture(ObservationScreen.Device);
        AllowGet(engine, "https://192.168.100.1/?_type=menuData&_tag=devBasicStatus", "{\"HardwareVersion\":\"V9.3.12\"}", "application/json");

        engine.Gets.Should().Contain(item => item.IsBaseline && item.Classification == ObservedGetClassification.Asset);
        engine.Gets.Should().Contain(item =>
            item.Screen == ObservationScreen.Device
            && item.IsNewOrChanged
            && item.Classification == ObservedGetClassification.DataEndpoint
            && item.Tag == "devBasicStatus");
    }

    [Fact]
    public void Changed_hash_is_highlighted()
    {
        using var engine = new ObservationEngine(Ont);
        AllowGet(engine, "https://192.168.100.1/?_type=menuData&_tag=statusLua", "{\"a\":1}", "application/json");
        engine.CloseBaseline();
        engine.StartScreenCapture(ObservationScreen.Pon);
        AllowGet(engine, "https://192.168.100.1/?_type=menuData&_tag=statusLua", "{\"a\":2}", "application/json");
        engine.Gets.Last().IsNewOrChanged.Should().BeTrue();
        engine.Gets.Last().Sha256.Should().NotBe(engine.Gets.First().Sha256);
    }

    [Fact]
    public void Cookies_and_tokens_are_removed_from_records()
    {
        using var engine = new ObservationEngine(Ont);
        var uri = new Uri("https://192.168.100.1/?_type=menuData&_tag=x&_sessionTOKEN=sekrit&SID=abc");
        engine.Evaluate(new IncomingObservationRequest("GET", uri));
        engine.CompleteGet(new IncomingObservationRequest("GET", uri), 200, "application/json", "{\"ok\":true}", "https://192.168.100.1/?_sessionTOKEN=sekrit");
        var record = engine.Gets.Single();
        record.Path.Should().NotContain("sekrit");
        record.ExtraValuesSanitized.Values.Should().OnlyContain(value => value == "[redacted]" || value.Length == 0);
        record.Initiator.Should().NotContain("sekrit");
        engine.ToSummaryText().Should().NotContain("sekrit");
        engine.ToSummaryText().Should().NotContain("SID_HTTPS_=");
    }

    [Fact]
    public void Serial_mac_loid_and_pppoe_are_masked()
    {
        var structure = ResponseStructureInspector.Inspect(
            "/data",
            "application/json",
            """{"SerialNumber":"ABC123XYZ789","MACAddress":"AA:BB:CC:DD:EE:FF","LOID":"loid-secret-99","Username":"user@isp","IPAddress":"200.1.2.3"}""");
        structure.MaskedSampleValues["SerialNumber"].Should().NotBe("ABC123XYZ789");
        structure.MaskedSampleValues["MACAddress"].Should().Be("AA:**:**:**:**:FF");
        structure.MaskedSampleValues["LOID"].Should().NotBe("loid-secret-99");
        structure.MaskedSampleValues["Username"].Should().NotBe("user@isp");
        structure.MaskedSampleValues["IPAddress"].Should().Be("200.1.x.x");
    }

    [Fact]
    public void Configuration_post_counter_stays_zero_and_posts_are_blocked()
    {
        using var engine = new ObservationEngine(Ont);
        engine.Evaluate(new IncomingObservationRequest("POST", new Uri("https://192.168.100.1/?_type=menuData&_tag=wanSave")));
        engine.Counters.PostsObservedAndBlocked.Should().Be(1);
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
        engine.Blocked.Should().Contain(item => item.Method == "POST");
    }

    [Fact]
    public void Other_ip_ends_observation_immediately()
    {
        using var engine = new ObservationEngine(Ont);
        var decision = engine.Evaluate(new IncomingObservationRequest("GET", new Uri("https://8.8.8.8/")));
        decision.Allowed.Should().BeFalse();
        engine.EndedByIpChange.Should().BeTrue();
        engine.IsCancelled.Should().BeTrue();
        engine.Evaluate(new IncomingObservationRequest("GET", new Uri("https://192.168.100.1/"))).Allowed.Should().BeFalse();
    }

    [Fact]
    public void Cancel_blocks_pending_requests()
    {
        using var engine = new ObservationEngine(Ont);
        engine.Cancel();
        var decision = engine.Evaluate(new IncomingObservationRequest("GET", new Uri("https://192.168.100.1/")));
        decision.Allowed.Should().BeFalse();
        decision.Reason.Should().Contain("cancelada");
        engine.CompleteGet(
            new IncomingObservationRequest("GET", new Uri("https://192.168.100.1/")),
            200,
            "text/html",
            "<html></html>",
            null).Should().BeNull();
    }

    [Fact]
    public void Repeated_static_assets_are_not_priority_candidates()
    {
        using var engine = new ObservationEngine(Ont);
        AllowGet(engine, "https://192.168.100.1/jquery.js", "function x(){}", "text/javascript");
        engine.CloseBaseline();
        engine.StartScreenCapture(ObservationScreen.WanStatus);
        AllowGet(engine, "https://192.168.100.1/jquery.js", "function x(){}", "text/javascript");
        var repeated = engine.Gets.Last();
        repeated.IsNewOrChanged.Should().BeFalse();
        ObservationClassifier.IsPriorityCandidate(repeated.Classification, repeated.IsNewOrChanged).Should().BeFalse();
    }

    [Fact]
    public void Unconfirmed_firmware_proposal_forbids_write()
    {
        using var engine = new ObservationEngine(Ont);
        engine.CloseBaseline();
        engine.StartScreenCapture(ObservationScreen.Device);
        AllowGet(engine, "https://192.168.100.1/?_type=menuData&_tag=devBasicStatus", "{\"SoftwareVersion\":\"V9.3.10P8N1\"}", "application/json");
        var proposals = ReadContractProposalBuilder.FromObservation(
            engine.Gets,
            engine.Structures,
            FirmwareCompatibility.Unconfirmed,
            null);
        proposals.Should().NotBeEmpty();
        proposals.Should().OnlyContain(item => item.WriteForbidden);
        proposals.Should().OnlyContain(item => item.FirmwareStatus == nameof(FirmwareCompatibility.Unconfirmed));
    }

    private static void AllowGet(ObservationEngine engine, string url, string body, string contentType)
    {
        var uri = new Uri(url);
        engine.Evaluate(new IncomingObservationRequest("GET", uri)).Allowed.Should().BeTrue();
        engine.CompleteGet(new IncomingObservationRequest("GET", uri), 200, contentType, body, null);
    }
}

public sealed class IsolatedObserverCleanupTests
{
    [Fact]
    public void Destroying_user_data_folder_removes_temporary_session_files()
    {
        var folder = Path.Combine(Path.GetTempPath(), "tanto-observer-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "Cookies"), "SID_HTTPS_=secret");
        IsolatedObserverCleanup.DestroyUserDataFolder(folder).Should().BeTrue();
        Directory.Exists(folder).Should().BeFalse();
    }
}
