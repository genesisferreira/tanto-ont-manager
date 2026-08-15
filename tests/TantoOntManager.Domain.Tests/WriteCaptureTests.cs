using System.Net;
using FluentAssertions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.Domain.Tests;

public sealed class WriteCaptureTests
{
    private static readonly IPAddress Ont = IPAddress.Parse("192.168.100.1");
    private const string Secret = "lab-pppoe-secret";
    private const string FormBody = "VlanEnable=1&VLANID=210&Password=" + Secret + "&MTU=1500&Apply=1";

    [Fact]
    public void Post_candidate_is_intercepted_before_network()
    {
        using var engine = Capturing();
        var decision = PostApply(engine);
        WriteCaptureEligibility.AllowsNetwork(decision).Should().BeFalse();
        decision.Allowed.Should().BeFalse();
        engine.WriteCandidate.Should().NotBeNull();
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
        engine.WriteCandidate!.NetworkRequestSent.Should().BeFalse();
        engine.WriteCandidate.BlockedBeforeNetwork.Should().BeTrue();
        engine.WriteCandidate.ConfigurationRequestsSent.Should().Be(0);
    }

    [Theory]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public void Mutating_method_is_blocked_before_network(string method)
    {
        using var engine = Capturing();
        var uri = new Uri("https://192.168.100.1/?_type=menuData&_tag=wanSave");
        var decision = engine.Evaluate(
            new IncomingObservationRequest(method, uri),
            Payload(FormBody));
        decision.Allowed.Should().BeFalse();
        WriteCaptureEligibility.AllowsNetwork(decision).Should().BeFalse();
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
        engine.WriteCandidate.Should().NotBeNull();
        engine.WriteCandidate!.Method.Should().Be(method);
    }

    [Fact]
    public void Request_to_other_ip_is_blocked_and_does_not_become_candidate()
    {
        using var engine = Capturing();
        var decision = engine.Evaluate(new IncomingObservationRequest(
            "POST",
            new Uri("https://192.168.1.1/?_tag=wanSave")));
        decision.Allowed.Should().BeFalse();
        decision.EndsObservation.Should().BeTrue();
        engine.EndedByIpChange.Should().BeTrue();
        engine.WriteCandidate.Should().BeNull();
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
    }

    [Fact]
    public void External_redirect_ends_observation()
    {
        using var engine = Capturing();
        var decision = engine.Evaluate(new IncomingObservationRequest(
            "GET",
            new Uri("https://192.168.100.1/"),
            RedirectLocation: new Uri("https://example.com/")));
        decision.Allowed.Should().BeFalse();
        decision.EndsObservation.Should().BeTrue();
        engine.EndedByIpChange.Should().BeTrue();
        engine.WriteCandidate.Should().BeNull();
    }

    [Fact]
    public void Login_entry_is_not_a_configuration_candidate()
    {
        using var engine = Capturing();
        var uri = new Uri("https://192.168.100.1/?_type=loginData&_tag=login_entry");
        engine.Evaluate(new IncomingObservationRequest("POST", uri), Payload("Username=admin&Password=admin"));
        engine.WriteCandidate.Should().BeNull();
        engine.Counters.ConfigurationRequestsBlocked.Should().Be(0);
        engine.Counters.PostsObservedAndBlocked.Should().Be(1);
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
    }

    [Fact]
    public void Logout_entry_is_not_a_configuration_candidate()
    {
        using var engine = Capturing();
        var uri = new Uri("https://192.168.100.1/?_type=loginData&_tag=logout_entry");
        engine.Evaluate(new IncomingObservationRequest("POST", uri), Payload("IF_LogOff=1"));
        engine.WriteCandidate.Should().BeNull();
        engine.Counters.ConfigurationRequestsBlocked.Should().Be(0);
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
    }

    [Fact]
    public void Ordered_field_names_are_preserved()
    {
        var fields = WriteBodyInspector.Inspect("application/x-www-form-urlencoded", FormBody);
        fields.Select(item => item.Name).Should().Equal("VlanEnable", "VLANID", "Password", "MTU", "Apply");
    }

    [Fact]
    public void Secret_values_are_redacted_and_pppoe_password_is_absent()
    {
        using var engine = Capturing();
        PostApply(engine);
        var password = engine.WriteCandidate!.Fields.Single(item => item.Name == "Password");
        password.Sensitive.Should().BeTrue();
        password.Value.Should().Be("[redacted]");
        password.LengthBucket.Should().Be("8-16");
        engine.WriteCandidate.StructureSha256.Should().NotContain(Secret);
        engine.ToSummaryText().Should().NotContain(Secret);
        var json = System.Text.Json.JsonSerializer.Serialize(engine.WriteCandidate);
        json.Should().NotContain(Secret);
        json.Should().Contain("[redacted]");
    }

    [Fact]
    public void Configuration_requests_sent_remain_zero()
    {
        using var engine = Capturing();
        PostApply(engine);
        engine.Evaluate(new IncomingObservationRequest("PUT", new Uri("https://192.168.100.1/?_tag=wanSave")));
        engine.Counters.ConfigurationPostsSent.Should().Be(0);
        engine.Snapshot().Counters.ConfigurationPostsSent.Should().Be(0);
        engine.WriteCandidate!.ConfigurationRequestsSent.Should().Be(0);
    }

    [Fact]
    public void At_most_one_candidate_is_captured_and_there_is_no_retry()
    {
        using var engine = Capturing();
        PostApply(engine);
        var first = engine.WriteCandidate;
        var second = engine.Evaluate(
            new IncomingObservationRequest("POST", new Uri("https://192.168.100.1/?_tag=wanCreate")),
            Payload("Create=1&Password=" + Secret));
        second.Allowed.Should().BeFalse();
        engine.WriteCandidatesShouldBeOne(first);
        engine.StartBlockedWriteCapture(WriteCaptureEligibility.CompatibleLab("MAPEAR F6201B"))
            .Error!.Code.Should().Be(ErrorCodes.WriteCaptureAlreadyUsed);
        engine.Counters.WriteCandidatesIntercepted.Should().Be(1);
    }

    [Fact]
    public void Exact_firmware_allows_capture()
    {
        using var engine = new ObservationEngine(Ont);
        engine.StartBlockedWriteCapture(WriteCaptureEligibility.CompatibleLab("MAPEAR F6201B"))
            .IsSuccess.Should().BeTrue();
        engine.WriteCaptureState.Should().Be(WriteCapturePhase.Capturing);
    }

    [Fact]
    public void Unconfirmed_firmware_refuses_capture()
    {
        using var engine = new ObservationEngine(Ont);
        var result = engine.StartBlockedWriteCapture(new WriteCaptureEligibilityInput(
            ManufacturerNames.Zte,
            DeviceModelIds.ZteF6201B,
            FirmwareCompatibility.Unconfirmed,
            WriteCaptureEligibility.ExpectedSoftware,
            true,
            "MAPEAR F6201B"));
        result.IsFailure.Should().BeTrue();
        result.Error!.Code.Should().Be(ErrorCodes.WriteCaptureFirmwareUnconfirmed);
        engine.WriteCaptureState.Should().Be(WriteCapturePhase.Idle);
    }

    [Fact]
    public void Incompatible_firmware_refuses_capture()
    {
        using var engine = new ObservationEngine(Ont);
        var result = engine.StartBlockedWriteCapture(new WriteCaptureEligibilityInput(
            ManufacturerNames.Zte,
            DeviceModelIds.ZteF6201B,
            FirmwareCompatibility.ConfirmedIncompatible,
            "V9.0.0P1N1",
            true,
            "MAPEAR F6201B"));
        result.IsFailure.Should().BeTrue();
        result.Error!.Code.Should().Be(ErrorCodes.WriteCaptureFirmwareIncompatible);
    }

    [Theory]
    [InlineData("mapear f6201b")]
    [InlineData("MAPEAR F6201B ")]
    [InlineData(" MAPEAR F6201B")]
    [InlineData("MAPEAR  F6201B")]
    [InlineData("")]
    public void Confirmation_other_than_exact_phrase_is_rejected(string confirmation)
    {
        WriteCaptureEligibility.IsExactConfirmation(confirmation).Should().BeFalse();
        using var engine = new ObservationEngine(Ont);
        engine.StartBlockedWriteCapture(WriteCaptureEligibility.CompatibleLab(confirmation))
            .Error!.Code.Should().Be(ErrorCodes.WriteCaptureConfirmationRejected);
    }

    [Fact]
    public void Safe_public_values_may_be_recorded()
    {
        var fields = WriteBodyInspector.Inspect("application/x-www-form-urlencoded", FormBody);
        fields.Single(item => item.Name == "VLANID").Value.Should().Be("210");
        fields.Single(item => item.Name == "MTU").Value.Should().Be("1500");
        fields.Single(item => item.Name == "VlanEnable").Value.Should().Be("1");
    }

    private static ObservationEngine Capturing()
    {
        var engine = new ObservationEngine(Ont);
        engine.StartBlockedWriteCapture(WriteCaptureEligibility.CompatibleLab("MAPEAR F6201B")).IsSuccess.Should().BeTrue();
        return engine;
    }

    private static ObservationDecision PostApply(ObservationEngine engine)
        => engine.Evaluate(
            new IncomingObservationRequest("POST", new Uri("https://192.168.100.1/?_type=menuData&_tag=wanSave")),
            Payload(FormBody));

    private static ObservedWritePayload Payload(string body)
        => WriteBodyInspector.ToPayload(
            "application/x-www-form-urlencoded",
            body,
            "https://192.168.100.1/?_type=menuView&_tag=ethWanConfig",
            "xhr",
            "Apply");
}

internal static class WriteCaptureTestExtensions
{
    public static void WriteCandidatesShouldBeOne(this ObservationEngine engine, WriteContractCandidate? first)
    {
        engine.WriteCandidate.Should().BeSameAs(first);
        engine.Counters.WriteCandidatesIntercepted.Should().Be(1);
        engine.WriteCaptureSpent.Should().BeTrue();
    }
}
