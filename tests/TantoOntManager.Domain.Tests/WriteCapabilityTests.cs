using System.Net;
using FluentAssertions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.Domain.Tests;

public sealed class WriteCapabilityTests
{
    private static readonly IPAddress Ont = IPAddress.Parse("192.168.100.1");

    [Fact]
    public void Dhcp_and_static_without_pppoe_after_footer_is_pppoe_option_unavailable()
    {
        using var engine = LabWanEngine();
        engine.IngestDomSnapshot(LabWanWithoutPppoe());

        var report = engine.WriteCapability;
        report.IpTypeOptions.Should().BeEquivalentTo("DHCP", "Static");
        report.PppoeAvailable.Should().Be(WriteCapabilityAvailability.Unavailable);
        report.CreateProfileAvailable.Should().Be(WriteCapabilityAvailability.Unavailable);
        report.ApplySaveAvailable.Should().Be(WriteCapabilityAvailability.Unavailable);
        report.Conclusion.Should().Be(WriteCapabilityConclusion.PppoeOptionUnavailable);
        report.Evidences.Select(item => item.Code).Should().Contain(new[]
        {
            "EVID.WAN_PAGE_OBSERVED",
            "EVID.FOOTER_REACHED",
            "EVID.IPTYPE_OPTIONS",
            "EVID.PPPOE_ABSENT"
        });
        report.OperatorMessage.Should().Be(WriteCapabilityReport.PppoeUnavailableOperatorMessage);
        report.ConfigurationRequestsSent.Should().Be(0);
        report.ObservedUsername.Should().Be("admin");
    }

    [Fact]
    public void Page_scrolled_to_footer_without_create_apply_save_is_recorded()
    {
        using var engine = LabWanEngine();
        engine.IngestDomSnapshot(LabWanWithoutPppoe());

        var report = engine.WriteCapability;
        report.PageScrolledToFooter.Should().BeTrue();
        report.CreateProfileAvailable.Should().Be(WriteCapabilityAvailability.Unavailable);
        report.ApplySaveAvailable.Should().Be(WriteCapabilityAvailability.Unavailable);
        report.Evidences.Select(item => item.Code).Should().Contain("EVID.CREATE_ABSENT");
        report.Evidences.Select(item => item.Code).Should().Contain("EVID.APPLY_SAVE_ABSENT");
    }

    [Fact]
    public void Disabled_readonly_and_hidden_controls_are_recorded()
    {
        using var engine = LabWanEngine();
        engine.IngestDomSnapshot(new WriteCapabilityDomSnapshot(
            ["Internet", "WAN"],
            [
                IpType("DHCP", "Static"),
                new ObservedDomControl("INPUT", "vlanId", "vlanId", "text", true, true, false, [], null, null, false),
                new ObservedDomControl("INPUT", "flag", "hiddenFlag", "hidden", false, false, true, [], null, null, false)
            ],
            true));

        var report = engine.WriteCapability;
        report.BlockedOrHiddenControls.Should().NotBeEmpty();
        report.Evidences.Select(item => item.Code).Should().Contain("EVID.DISABLED_READONLY_HIDDEN");
    }

    [Fact]
    public void Isolated_missing_button_is_not_a_definitive_conclusion()
    {
        using var engine = LabWanEngine();
        engine.IngestDomSnapshot(new WriteCapabilityDomSnapshot(["WAN"], [], false));

        var report = engine.WriteCapability;
        report.Conclusion.Should().Be(WriteCapabilityConclusion.InsufficientEvidence);
        report.Conclusion.Should().NotBe(WriteCapabilityConclusion.ReadOnlyAccount);
        report.Conclusion.Should().NotBe(WriteCapabilityConclusion.PresetLocked);
        report.Evidences.Select(item => item.Code).Should().Contain("EVID.ISOLATED_ABSENCE_NOT_CONCLUSIVE");
    }

    [Fact]
    public void Evidence_set_from_lab_ui_is_pppoe_option_unavailable()
    {
        var report = WriteCapabilityClassifier.Evaluate(new WriteCapabilityFacts(
            "ZTE",
            "F6201B",
            FirmwareCompatibility.ConfirmedCompatible,
            "V9.3.10P8N1",
            "admin",
            ["Internet", "WAN", "Status"],
            ["HSI_TR069", "VOIP_IPTV"],
            [],
            [],
            ["DHCP", "Static"],
            [IpType("DHCP", "Static")],
            true,
            true,
            0,
            0));

        report.Conclusion.Should().Be(WriteCapabilityConclusion.PppoeOptionUnavailable);
        report.PppoeAvailable.Should().Be(WriteCapabilityAvailability.Unavailable);
        report.CreateProfileAvailable.Should().Be(WriteCapabilityAvailability.Unavailable);
        report.ApplySaveAvailable.Should().Be(WriteCapabilityAvailability.Unavailable);
    }

    [Fact]
    public void Read_only_account_requires_multiple_evidences()
    {
        var isolated = WriteCapabilityClassifier.Evaluate(new WriteCapabilityFacts(
            "ZTE",
            "F6201B",
            FirmwareCompatibility.ConfirmedCompatible,
            "V9.3.10P8N1",
            "admin",
            [],
            ["HSI_TR069"],
            [],
            [],
            [],
            [],
            false,
            true,
            0,
            0));
        isolated.Conclusion.Should().NotBe(WriteCapabilityConclusion.ReadOnlyAccount);

        var report = WriteCapabilityClassifier.Evaluate(new WriteCapabilityFacts(
            "ZTE",
            "F6201B",
            FirmwareCompatibility.ConfirmedCompatible,
            "V9.3.10P8N1",
            "admin",
            ["Internet", "WAN", "Status"],
            ["HSI_TR069"],
            [],
            [],
            [],
            [
                new ObservedDomControl("INPUT", "vlanId", "vlanId", "text", true, true, false, [], null, null, false)
            ],
            true,
            true,
            0,
            0));

        report.Conclusion.Should().Be(WriteCapabilityConclusion.ReadOnlyAccount);
        report.Evidences.Select(item => item.Code).Should().Contain(new[]
        {
            "EVID.WAN_PAGE_OBSERVED",
            "EVID.FOOTER_REACHED",
            "EVID.CREATE_ABSENT",
            "EVID.APPLY_SAVE_ABSENT",
            "EVID.DISABLED_READONLY_HIDDEN",
            "EVID.MENU_WITHOUT_WRITE_LEAVES"
        });
    }

    [Fact]
    public void Fixed_dom_script_does_not_read_sensitive_values_or_invoke_events()
    {
        WriteCapabilityDomScript.IsSafe().Should().BeTrue();
        WriteCapabilityDomScript.Source.Should().NotContain("click(");
        WriteCapabilityDomScript.Source.Should().NotContain("dispatchEvent");
        WriteCapabilityDomScript.Source.Should().NotContain("innerHTML");
        WriteCapabilityDomScript.Source.Should().NotContain(".submit(");
        WriteCapabilityDomScript.Source.Should().NotContain("el.value");
        WriteCapabilityDomScript.Source.Should().NotContain("Apply(");
        WriteCapabilityDomScript.Source.Should().NotContain("Save(");
        WriteCapabilityDomScript.Source.Should().Contain("isPwd(el)");
        WriteCapabilityDomScript.Source.Should().Contain("==='password'");
    }

    [Fact]
    public void Dom_parser_drops_password_fields_and_keeps_public_options()
    {
        var json = """
            {"menu":["Internet","WAN"],"footer":true,"controls":[
              {"tag":"INPUT","name":"Password","id":"pwd","type":"password","disabled":false,"readOnly":false,"hidden":false,"options":["secret"],"buttonText":"x","handler":null,"sensitive":true},
              {"tag":"SELECT","name":"IPType","id":"ipType","type":"select-one","disabled":true,"readOnly":false,"hidden":false,"options":["DHCP","Static","PPPoE"],"buttonText":null,"handler":null,"sensitive":false}
            ]}
            """;
        var snapshot = WriteCapabilityDomParser.Parse(json);
        snapshot.PageScrolledToFooter.Should().BeTrue();
        snapshot.Controls.Should().HaveCount(2);
        snapshot.Controls[0].Sensitive.Should().BeTrue();
        snapshot.Controls[0].Name.Should().BeNull();
        snapshot.Controls[0].Id.Should().BeNull();
        snapshot.Controls[0].OptionValues.Should().BeEmpty();
        snapshot.Controls[1].OptionValues.Should().Equal("DHCP", "Static", "PPPoE");
        snapshot.Controls[1].Disabled.Should().BeTrue();
    }

    [Fact]
    public void Pppoe_remains_a_public_enumeration()
        => WriteCapabilityTokenScanner.IsPublicEnumeration("PPPoE").Should().BeTrue();

    [Fact]
    public void Get_hints_without_footer_do_not_conclude_pppoe_unavailable()
    {
        using var engine = new ObservationEngine(Ont);
        engine.SetCapabilityContext(LabContext());
        engine.CompleteGet(
            new IncomingObservationRequest("GET", new Uri("https://192.168.100.1/?_type=menuData&_tag=wan_internet_lua.lua")),
            200,
            "text/xml",
            "<ajax_response_xml_root>DHCP Static</ajax_response_xml_root>",
            null);

        var report = engine.WriteCapability;
        report.WanPageObserved.Should().BeTrue();
        report.PageScrolledToFooter.Should().BeFalse();
        report.Conclusion.Should().Be(WriteCapabilityConclusion.InsufficientEvidence);
        report.Conclusion.Should().NotBe(WriteCapabilityConclusion.PppoeOptionUnavailable);
        report.ConfigurationRequestsSent.Should().Be(0);
    }

    [Fact]
    public void Promotion_is_blocked_with_zero_candidates()
    {
        using var engine = LabWanEngine();
        engine.IngestDomSnapshot(WriteUiAvailable());
        var gate = WriteContractPromotionGate.Evaluate(engine.Snapshot());
        gate.IsFailure.Should().BeTrue();
        gate.Error!.Code.Should().Be(ErrorCodes.WritePromotionBlocked);
        gate.Error.Message.Should().Contain("candidatos interceptados = 0");
    }

    [Fact]
    public void Promotion_is_blocked_without_pppoe()
    {
        using var engine = LabWanEngine();
        engine.StartBlockedWriteCapture(WriteCaptureEligibility.CompatibleLab("MAPEAR F6201B")).IsSuccess.Should().BeTrue();
        engine.Evaluate(
            new IncomingObservationRequest("POST", new Uri("https://192.168.100.1/?_type=menuData&_tag=wanSave")),
            WriteBodyInspector.ToPayload(
                "application/x-www-form-urlencoded",
                "VlanEnable=1&VLANID=210&MTU=1500&Apply=1",
                "https://192.168.100.1/?_type=menuView&_tag=ethWanConfig",
                "xhr",
                "Apply"));
        engine.IngestDomSnapshot(LabWanWithoutPppoe());

        var gate = WriteContractPromotionGate.Evaluate(engine.Snapshot());
        gate.IsFailure.Should().BeTrue();
        gate.Error!.Code.Should().Be(ErrorCodes.WritePromotionBlocked);
        gate.Error.Message.Should().Contain("PPPoE");
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
        engine.WriteCapability.Conclusion.Should().Be(WriteCapabilityConclusion.PppoeOptionUnavailable);
        engine.WriteCapability.ConfigurationRequestsSent.Should().Be(0);
    }

    [Fact]
    public void Operator_text_includes_required_message_when_pppoe_and_create_are_unavailable()
    {
        using var engine = LabWanEngine();
        engine.IngestDomSnapshot(LabWanWithoutPppoe());
        var text = WriteCapabilityClassifier.ToOperatorText(engine.WriteCapability);
        text.Should().Contain("PPPoE disponível: Não");
        text.Should().Contain("Criar perfil disponível: Não");
        text.Should().Contain("Apply/Save disponível: Não");
        text.Should().Contain(WriteCapabilityReport.PppoeUnavailableOperatorMessage);
        text.Should().Contain("Requisições de configuração enviadas: 0");
    }

    private static ObservationEngine LabWanEngine()
    {
        var engine = new ObservationEngine(Ont);
        engine.SetCapabilityContext(LabContext());
        engine.StartScreenCapture(ObservationScreen.WanConfig);
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

    private static WriteCapabilityDomSnapshot LabWanWithoutPppoe()
        => new(
            ["Internet", "WAN", "Status"],
            [IpType("DHCP", "Static")],
            true);

    private static WriteCapabilityDomSnapshot WriteUiAvailable()
        => new(
            ["Internet", "WAN"],
            [
                IpType("DHCP", "Static", "PPPoE"),
                new ObservedDomControl("BUTTON", "btnApply", "Apply", "submit", false, false, false, [], "Apply", "onApply", false),
                new ObservedDomControl("BUTTON", "btnAdd", "Add", "button", false, false, false, [], "Create New Item", "onCreate", false)
            ],
            true);

    private static ObservedDomControl IpType(params string[] options)
        => new("SELECT", "IPType", "ipType", "select-one", false, false, false, options, null, null, false);
}
