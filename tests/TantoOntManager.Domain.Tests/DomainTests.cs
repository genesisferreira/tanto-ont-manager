using System.Net;
using FluentAssertions;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.Domain.Tests;

public sealed class SensitiveDataMaskerTests
{
    [Fact]
    public void MaskSerial_hides_the_middle()
    {
        SensitiveDataMasker.MaskSerial("ABC123XYZ789").Should().Be("ABC******789");
    }

    [Fact]
    public void MaskMac_keeps_only_first_and_last_octet()
    {
        SensitiveDataMasker.MaskMac("AA:BB:CC:DD:EE:FF").Should().Be("AA:**:**:**:**:FF");
    }

    [Fact]
    public void SanitizeLogText_redacts_password_cookie_and_authorization()
    {
        var raw = "password=secret123; Cookie: session=abc; Authorization: Bearer tok";
        var sanitized = SensitiveDataMasker.SanitizeLogText(raw);
        sanitized.Should().NotContain("secret123");
        sanitized.Should().NotContain("session=abc");
        sanitized.Should().NotContain("Bearer tok");
        sanitized.Should().Contain("[redacted]");
    }
}

public sealed class SubnetTests
{
    [Fact]
    public void Detects_same_subnet()
    {
        var config = new Ipv4Configuration(IPAddress.Parse("192.168.100.10"), IPAddress.Parse("255.255.255.0"));
        config.IsInSameSubnet(IPAddress.Parse("192.168.100.1")).Should().BeTrue();
        config.IsInSameSubnet(IPAddress.Parse("192.168.1.1")).Should().BeFalse();
    }

    [Fact]
    public void Suggestion_for_100_network_is_documented_and_not_applied()
    {
        var suggestion = SubnetSuggestion.ForTarget(KnownOntAddresses.ZteLocal100);
        suggestion.Should().NotBeNull();
        suggestion!.SuggestedHostAddress.ToString().Should().Be("192.168.100.10");
        suggestion.SubnetMask.ToString().Should().Be("255.255.255.0");
        suggestion.Gateway.ToString().Should().Be("192.168.100.1");
        suggestion.ToOperatorText().Should().Contain("não altera");
    }
}

public sealed class ResultTests
{
    [Fact]
    public void Failure_requires_error()
    {
        var result = Result.Failure<string>(Error.Create(ErrorCodes.HostUnreachable, "sem resposta"));
        result.IsFailure.Should().BeTrue();
        result.Error!.Code.Should().Be(ErrorCodes.HostUnreachable);
    }
}

public sealed class KnownAddressTests
{
    [Fact]
    public void Allows_only_known_or_explicit_custom_addresses()
    {
        KnownOntAddresses.IsKnownOrExplicitlyProvided(IPAddress.Parse("192.168.100.1"), null).Should().BeTrue();
        KnownOntAddresses.IsKnownOrExplicitlyProvided(IPAddress.Parse("10.0.0.1"), null).Should().BeFalse();
        KnownOntAddresses.IsKnownOrExplicitlyProvided(IPAddress.Parse("10.0.0.1"), IPAddress.Parse("10.0.0.1")).Should().BeTrue();
    }
}

public sealed class OperationModeTests
{
    [Fact]
    public void Laboratory_label_is_explicit()
    {
        OperationMode.LaboratoryReadOnly.ToUiLabel().Should().Be("Laboratório — somente leitura");
    }
}
