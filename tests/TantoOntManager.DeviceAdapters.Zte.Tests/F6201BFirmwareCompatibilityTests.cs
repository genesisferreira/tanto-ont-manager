using FluentAssertions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class F6201BFirmwareCompatibilityTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Unknown")]
    [InlineData("Desconhecido")]
    [InlineData("N/A")]
    [InlineData("null")]
    [InlineData("none")]
    [InlineData("---")]
    [InlineData("Não disponível na interface pública")]
    [InlineData("IPv4")]
    [InlineData("V9.3.12")]
    public void Absence_or_unreliable_value_is_unconfirmed(string? software)
    {
        F6201BFirmwareCompatibility.Classify(software).Should().Be(FirmwareCompatibility.Unconfirmed);
        F6201BFirmwareCompatibility.AllowsAuthenticationAndSafeRead(FirmwareCompatibility.Unconfirmed).Should().BeTrue();
        F6201BFirmwareCompatibility.AllowsWrite(FirmwareCompatibility.Unconfirmed).Should().BeFalse();
    }

    [Fact]
    public void Exact_homologated_version_is_confirmed_compatible()
    {
        F6201BFirmwareCompatibility.Classify("V9.3.10P8N1").Should().Be(FirmwareCompatibility.ConfirmedCompatible);
        F6201BFirmwareCompatibility.AllowsWrite(FirmwareCompatibility.ConfirmedCompatible).Should().BeFalse();
    }

    [Fact]
    public void Normalized_homologated_version_is_confirmed_compatible()
    {
        F6201BFirmwareCompatibility.Classify("v9.3.10 p8n1").Should().Be(FirmwareCompatibility.ConfirmedCompatible);
        F6201BFirmwareCompatibility.Classify("  V9.3.10P8N1  ").Should().Be(FirmwareCompatibility.ConfirmedCompatible);
    }

    [Fact]
    public void Real_different_software_is_confirmed_incompatible()
    {
        F6201BFirmwareCompatibility.Classify("V9.3.10P9N1").Should().Be(FirmwareCompatibility.ConfirmedIncompatible);
        F6201BFirmwareCompatibility.AllowsAuthenticationAndSafeRead(FirmwareCompatibility.ConfirmedIncompatible).Should().BeFalse();
        F6201BFirmwareCompatibility.AllowsWrite(FirmwareCompatibility.ConfirmedIncompatible).Should().BeFalse();
        F6201BFirmwareCompatibility.SanitizeForOperator("V9.3.10P9N1").Should().Be("V9.3.10P9N1");
    }

    [Fact]
    public void Missing_device_page_does_not_invent_firmware()
    {
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse(("/", "<html><body>Dashboard</body></html>"));
        parsed.SoftwareVersion.Should().BeNull();
        var identity = F6201BV9310P8N1AuthenticatedPageParser.ToIdentity("ZTE", "F6201B", parsed);
        F6201BV9310P8N1AuthenticatedPageParser.ClassifyFirmware(identity).Should().Be(FirmwareCompatibility.Unconfirmed);
        F6201BV9310P8N1AuthenticatedPageParser.FirmwareMatchesWhenPresent(identity).Should().BeTrue();
    }

    [Fact]
    public void Wan_version_field_is_not_treated_as_software_firmware()
    {
        var wan = """
                  <table>
                    <tr><td>Version</td><td>IPv4</td></tr>
                    <tr><td>Status</td><td>Connected</td></tr>
                  </table>
                  """;
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse(("/?_type=menuView&_tag=ethWanStatus", wan));
        parsed.SoftwareVersion.Should().BeNull();
        F6201BFirmwareCompatibility.Classify(parsed.SoftwareVersion).Should().Be(FirmwareCompatibility.Unconfirmed);
    }

    [Fact]
    public void Unavailable_software_on_device_page_is_unconfirmed()
    {
        var html = """
                   <table>
                     <tr><td>Hardware Version</td><td>V9.3.12</td></tr>
                     <tr><td>Software Version</td><td>Não disponível na interface pública</td></tr>
                   </table>
                   """;
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse(("/?_type=menuView&_tag=devinfo", html));
        parsed.SoftwareVersion.Should().Be("Não disponível na interface pública");
        F6201BFirmwareCompatibility.Classify(parsed.SoftwareVersion).Should().Be(FirmwareCompatibility.Unconfirmed);
    }

    [Fact]
    public void Device_information_is_prioritized_before_wan()
    {
        var html = """
                   <a MenuPage='ethWanStatus'>Internet → WAN</a>
                   <a MenuPage='devinfo'>Device Information</a>
                   """;
        var items = F6201BSafeReadDiscovery.Discover(html)
            .Where(item => item.Classification == SafeReadClassification.SafeRead)
            .ToList();
        items.Should().NotBeEmpty();
        F6201BFirmwareCompatibility.LooksLikeDeviceInformation(items[0]).Should().BeTrue();
        items[0].Tag.Should().Be("devinfo");
    }

    [Fact]
    public void Authenticated_unconfirmed_label_is_stable()
    {
        FirmwareCompatibility.Unconfirmed.ToAuthenticatedUiLabel()
            .Should().Be("Autenticado — somente leitura; firmware ainda não confirmada");
        FirmwareCompatibility.ConfirmedCompatible.ToAuthenticatedUiLabel()
            .Should().Be("Autenticado — somente leitura");
    }
}
