using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class F6201BDirectedReadTests
{
    private static string Fixture(string name)
        => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Statusmgr_shell_exposes_literal_device_information_tag()
    {
        var items = F6201BSafeReadDiscovery.Discover(Fixture("zte-f6201b-v9310p8n1-statusmgr-shell.html"), "/?_type=menuView&_tag=statusMgr");
        items.Should().Contain(item => item.Tag == "devBasicStatus" && item.Classification == SafeReadClassification.SafeRead);
        items.Should().NotContain(item => item.Tag == "devInfo" || item.Tag == "deviceInfo");
    }

    [Fact]
    public void Wan_version_ipv4_is_not_firmware()
    {
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse((
            "/?_type=menuView&_tag=ethWanStatus",
            "<table><tr><td>Version</td><td>IPv4</td></tr></table>"));
        parsed.SoftwareVersion.Should().BeNull();
        F6201BFirmwareCompatibility.Classify(parsed.SoftwareVersion).Should().Be(FirmwareCompatibility.Unconfirmed);
        F6201BFieldAssociation.IsExactSoftwareFirmwareField("Version").Should().BeFalse();
    }

    [Fact]
    public void Exact_software_version_field_confirms_firmware()
    {
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse((
            "/?_type=menuData&_tag=devBasicStatus",
            Fixture("zte-f6201b-v9310p8n1-statusmgr-device-data.html")));
        parsed.SoftwareVersion.Should().Be("V9.3.10P8N1");
        parsed.HardwareVersion.Should().Be("V9.3.12");
        parsed.BootVersion.Should().Be("V9.3.10P10N6");
        F6201BFirmwareCompatibility.Classify(parsed.SoftwareVersion).Should().Be(FirmwareCompatibility.ConfirmedCompatible);
    }

    [Fact]
    public void Pon_reads_separate_cells_and_ignores_transmit_receive_labels()
    {
        var parsed = F6201BV9310P8N1PonParser.Parse(("/?_type=menuView&_tag=ponOpticalInfo", Fixture("zte-f6201b-v9310p8n1-pon-structured.html")));
        parsed.OnuState.Should().Be("O5");
        parsed.InputPower.Should().Contain("-18.12");
        parsed.OutputPower.Should().Contain("2.15");
        parsed.InputPower.Should().NotContain("Transmit");
        parsed.OutputPower.Should().NotContain("Receive");
        parsed.BiasCurrent.Should().Contain("12.4");
        parsed.BiasCurrent.Should().NotBe("Transmit");
    }

    [Fact]
    public void Onu_state_minus_one_is_unknown_and_keeps_raw()
    {
        var parsed = F6201BV9310P8N1PonParser.Parse(("/?_type=menuView&_tag=ponOpticalInfo", Fixture("zte-f6201b-v9310p8n1-pon-onu-unknown.html")));
        parsed.OnuState.Should().Be("-1");
        PonState.FormatOnuState(parsed.OnuState, true).Should().Be("Desconhecido (-1)");
    }

    [Fact]
    public void Wan_concatenated_html_does_not_invent_profiles()
    {
        var parsed = F6201BV9310P8N1WanParser.Parse(("/?_type=menuView&_tag=ethWanStatus", Fixture("zte-f6201b-v9310p8n1-wan-concat-trap.html")));
        parsed.Profiles.Should().BeEmpty();
    }

    [Fact]
    public void Wan_structured_table_keeps_two_independent_profiles()
    {
        var parsed = F6201BV9310P8N1WanParser.Parse(("/?_type=menuView&_tag=ethWanStatus", Fixture("zte-f6201b-v9310p8n1-wan-structured.html")));
        parsed.Profiles.Should().HaveCount(2);
        parsed.Profiles[0].Name.Should().Be("HSI_TR069");
        parsed.Profiles[1].Name.Should().Be("VOIP_IPTV");
        parsed.Profiles[0].ServiceList.Should().NotContain("VOIP_IPTV");
        parsed.Profiles[1].ServiceList.Should().NotContain("HSI_TR069");
        parsed.Profiles[0].VlanId.Should().Be(210);
        parsed.Profiles[1].VlanId.Should().Be(220);
    }

    [Fact]
    public void Discovery_allows_menuview_ethwanconfig_and_blocks_mutations()
    {
        var html = Fixture("zte-f6201b-v9310p8n1-directed-menu.html");
        var items = F6201BSafeReadDiscovery.Discover(html);
        items.Should().Contain(item => item.Tag == "ethWanConfig"
                                      && item.TypeAndTag.StartsWith("menuView")
                                      && item.Classification == SafeReadClassification.SafeRead);
        items.Should().Contain(item => item.Tag == "wan_apply" && item.Classification == SafeReadClassification.BlockedPotentialAction);
        items.Should().Contain(item => item.Tag == "wanSave" && item.Classification == SafeReadClassification.BlockedPotentialAction);
        items.Should().NotContain(item => item.Tag == "ethWanConfig" && item.TypeAndTag.StartsWith("menuData") && item.Classification == SafeReadClassification.SafeRead);
    }

    [Fact]
    public async Task Directed_read_fetches_device_pon_wan_before_secondary()
    {
        var transport = new DirectedTransport();
        var result = await F6201BAuthenticatedReadMapper.MapAsync(
            transport,
            EmptySnapshot(),
            NullLogger.Instance,
            CancellationToken.None);

        transport.Posts.Should().BeEmpty();
        transport.ConfigPostCount.Should().Be(0);
        transport.Gets.Should().Contain(uri => uri.Contains("_tag=statusMgr"));
        transport.Gets.Should().Contain(uri => uri.Contains("_tag=devBasicStatus"));
        transport.Gets.Should().Contain(uri => uri.Contains("ponOpticalInfo"));
        transport.Gets.Should().Contain(uri => uri.Contains("ethWanStatus"));
        transport.Gets.Should().Contain(uri => uri.Contains("ethWanConfig") && uri.Contains("menuView"));
        transport.Gets.Should().NotContain(uri => uri.Contains("wan_apply"));
        transport.Gets.Should().NotContain(uri => uri.Contains("wanSave"));

        var dataGets = transport.Gets.Where(uri => uri.Contains("_tag=")).ToList();
        var statusMgr = dataGets.FindIndex(uri => uri.Contains("statusMgr"));
        var pon = dataGets.FindIndex(uri => uri.Contains("ponOpticalInfo"));
        var wan = dataGets.FindIndex(uri => uri.Contains("ethWanStatus"));
        var firewall = dataGets.FindIndex(uri => uri.Contains("firewallFilter"));
        statusMgr.Should().BeGreaterThanOrEqualTo(0);
        pon.Should().BeGreaterThan(statusMgr);
        wan.Should().BeGreaterThan(pon);
        if (firewall >= 0)
        {
            firewall.Should().BeGreaterThan(wan);
        }

        result.Snapshot.FirmwareCompatibility.Should().Be(FirmwareCompatibility.ConfirmedCompatible);
        result.Snapshot.Diagnostics.Pon.OnuState.Should().Be("O5");
        result.Snapshot.Diagnostics.WanProfiles.Should().HaveCount(2);
        result.Map.DirectedReads.Should().Contain(item => item.Priority == "Device" && item.GetsUsed <= 10);
        result.Map.DirectedReads.Should().Contain(item => item.Priority == "Pon" && item.GetsUsed <= 12);
        result.Map.DirectedReads.Should().Contain(item => item.Priority == "Wan" && item.GetsUsed <= 16);
        result.Map.ToOperatorText().Should().Contain("Leitura dirigida");
        result.Map.ConfigPostCount.Should().Be(0);
        var joined = string.Join('\n', transport.Gets);
        joined.Should().NotContain("lab-pass");
        joined.Should().NotContain("SID_HTTPS_");
    }

    private static AuthenticatedReadSnapshot EmptySnapshot()
        => new(
            new DeviceIdentity(ManufacturerNames.Zte, DeviceModelIds.ZteF6201B, FirmwareInfo.Unknown, null, null),
            DeviceDiagnostics.PublicInterfaceOnly("aguardando mapa"),
            ["/"],
            1,
            0,
            "200",
            "homehash",
            TimeSpan.Zero,
            F6201BV9310P8N1AuthContract.AdapterId,
            [],
            [],
            1,
            0,
            0);

    private sealed class DirectedTransport : IBoundOntTransport
    {
        public List<string> Gets { get; } = [];
        public List<string> Posts { get; } = [];
        public IPAddress BoundAddress { get; } = IPAddress.Parse("192.168.100.1");
        public string? ObservedCertificateSha256 => "abc";
        public bool HasSessionCookie => true;
        public int PostCount => 1;
        public int LoginPostCount => 1;
        public int LogoutPostCount => 0;
        public int ConfigPostCount => 0;
        public string? SessionToken => "tok";
        public string SessionId => "directed";
        public int HttpClientInstanceId => 1;
        public int CookieCount => 1;
        public IReadOnlyList<string> HttpMethodsUsed => Gets.Select(_ => "GET").ToList();
        public IReadOnlyList<string> MaskedGetPages => Gets;
        public IReadOnlyList<string> MaskedPosts => Posts;

        public Task<BoundHttpResult> GetAsync(string pathAndQuery, CancellationToken cancellationToken)
        {
            Gets.Add(pathAndQuery);
            string body;
            if (pathAndQuery == "/")
            {
                body = Fixture("zte-f6201b-v9310p8n1-directed-menu.html");
            }
            else if (pathAndQuery.Contains("statusMgr", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-statusmgr-shell.html");
            }
            else if (pathAndQuery.Contains("devBasicStatus", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-statusmgr-device-data.html");
            }
            else if (pathAndQuery.Contains("ponOptical", StringComparison.OrdinalIgnoreCase)
                     || pathAndQuery.Contains("ponSn", StringComparison.OrdinalIgnoreCase)
                     || pathAndQuery.Contains("ponLoid", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-pon-structured.html");
            }
            else if (pathAndQuery.Contains("ethWanConfig", StringComparison.OrdinalIgnoreCase))
            {
                body = "<html><body>WAN template GET</body></html>";
            }
            else if (pathAndQuery.Contains("ethWan", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-wan.json");
            }
            else
            {
                body = "<html><body>secondary</body></html>";
            }

            var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant()[..8];
            return Task.FromResult(new BoundHttpResult(true, 200, body, "text/html", "https://192.168.100.1" + pathAndQuery, 0, hash, TimeSpan.Zero, null));
        }

        public Task<BoundHttpResult> PostLoginFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
        {
            Posts.Add("login");
            return Task.FromResult(BoundHttpResult.Fail(Error.Create(ErrorCodes.PostNotAllowed, "POST recusado")));
        }

        public Task<BoundHttpResult> PostLogoutFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
        {
            Posts.Add("logout");
            return Task.FromResult(BoundHttpResult.Fail(Error.Create(ErrorCodes.PostNotAllowed, "POST recusado")));
        }

        public void RememberSafeRead(string type, string tag)
        {
        }

        public void RememberReferencedAsset(string relativePath)
        {
        }

        public void ClearCookiesAndState(string reason)
        {
        }

        public void Dispose()
        {
        }
    }
}
