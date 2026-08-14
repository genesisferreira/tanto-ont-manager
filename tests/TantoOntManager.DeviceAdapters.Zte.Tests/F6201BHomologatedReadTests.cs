using System.Net;
using System.Text;
using FluentAssertions;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class F6201BHomologatedReadTests
{
    private static string Fixture(string name)
        => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Resolves_observed_get_routes_and_extra_parameters()
    {
        var device = F6201BV9310P8N1HomologatedReadContract.BuildPath(
            F6201BV9310P8N1HomologatedReadContract.Device, "1786744850797");
        var pon = F6201BV9310P8N1HomologatedReadContract.BuildPath(
            F6201BV9310P8N1HomologatedReadContract.Pon, "1786744850802");
        var status = F6201BV9310P8N1HomologatedReadContract.BuildPath(
            F6201BV9310P8N1HomologatedReadContract.WanStatus, "1786744850811");
        var config = F6201BV9310P8N1HomologatedReadContract.BuildPath(
            F6201BV9310P8N1HomologatedReadContract.WanConfig, "1786744850823");

        device.Should().Contain("_type=menuData").And.Contain("_tag=devmgr_statusmgr_lua.lua").And.Contain("_=1786744850797");
        pon.Should().Contain("_tag=optical_info_lua.lua");
        status.Should().Contain("_tag=wan_internetstatus_lua.lua").And.Contain("TypeUplink=2").And.Contain("pageType=1");
        config.Should().Contain("_tag=wan_internet_lua.lua").And.Contain("TypeUplink=2").And.Contain("pageType=0");
        status.Should().NotContain("pageType=0");
        config.Should().NotContain("pageType=1");
        F6201BGetUrl.Identity(status).Should().Be(
            F6201BGetUrl.Identity(F6201BV9310P8N1HomologatedReadContract.BuildPath(
                F6201BV9310P8N1HomologatedReadContract.WanStatus, "999")));
    }

    [Fact]
    public void Temporary_folder_is_never_used_as_runtime_and_lua_tags_are_valid()
    {
        F6201BV9310P8N1AuthContract.IsValidTag("devmgr_statusmgr_lua.lua").Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsValidTag("optical_info_lua.lua").Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsValidTag("wan_internetstatus_lua.lua").Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsValidTag("wan_internet_lua.lua").Should().BeTrue();
        F6201BProvenQueryParameter.IsCacheBuster("_", "1786744850811").Should().BeTrue();
    }

    [Fact]
    public void Allowlist_keeps_observed_extras_and_rejects_other_ip()
    {
        var ip = IPAddress.Parse("192.168.100.1");
        var keys = new[] { "menuData:wan_internetstatus_lua.lua" };
        bool Proven(string key, string name, string value)
            => key == "menuData:wan_internetstatus_lua.lua"
               && ((name == "TypeUplink" && value == "2") || (name == "pageType" && value == "1"));

        F6201BV9310P8N1AuthContract.IsAllowedGet(
            new Uri("https://192.168.100.1/?_type=menuData&_tag=wan_internetstatus_lua.lua&TypeUplink=2&pageType=1&_=1786744850811"),
            ip,
            keys,
            Proven).Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsAllowedGet(
            new Uri("https://192.168.1.1/?_type=menuData&_tag=wan_internetstatus_lua.lua&TypeUplink=2&pageType=1&_=1"),
            ip,
            keys,
            Proven).Should().BeFalse();
    }

    [Fact]
    public async Task Reads_device_pon_and_two_wan_profiles_from_xml()
    {
        var transport = new HomologatedTransport();
        var result = await F6201BHomologatedReadCoordinator.ReadAsync(transport, CancellationToken.None);

        result.FirmwareCompatibility.Should().Be(FirmwareCompatibility.ConfirmedCompatible);
        result.Device.DeviceType.Should().Be("F6201B");
        result.Device.HardwareVersion.Should().Be("V9.3.12");
        result.Device.SoftwareVersion.Should().Be("V9.3.10P8N1");
        result.Device.BootVersion.Should().Be("V9.3.10P10N6");
        result.Pon.OnuState.Should().Be("Initial State(o1)");
        result.Pon.OnuState.Should().NotBe("O1");
        result.Pon.InputPower.Should().Be("--");
        result.Pon.OutputPower.Should().Be("--");
        result.Pon.BiasCurrent.Should().NotBe(result.Pon.InputPower);
        result.Pon.BiasCurrent.Should().NotBe(result.Pon.OutputPower);
        result.Pon.Voltage.Should().Contain("3205");
        result.Pon.BiasCurrent.Should().Contain("0.002");
        result.Pon.Temperature.Should().Contain("55.835");
        result.Wan.Profiles.Should().HaveCount(2);
        result.Wan.Profiles[0].Name.Should().Be("HSI_TR069");
        result.Wan.Profiles[1].Name.Should().Be("VOIP_IPTV");
        result.Wan.Profiles[0].VlanId.Should().Be(210);
        result.Wan.Profiles[1].VlanId.Should().Be(220);
        result.Wan.Profiles[0].ServiceList.Should().Be("INTERNET_TR069");
        result.Wan.Profiles[1].ServiceList.Should().Be("INTERNET_VoIP");
        result.Wan.Profiles[0].Mtu.Should().Be("1500");
        result.Wan.Profiles[0].NatEnabled.Should().BeTrue();
        result.Wan.Profiles.Should().OnlyContain(profile => profile.PppoeUsername != "user@isp");
        string.Join('\n', result.Wan.Evidence.Select(item => item.Snippet + item.Value)).Should().NotContain("secret-lab");
        result.Device.SerialNumber.Should().Be("ZTEG00LAB001");
        SensitiveDataMaskerShouldHide(result);
        transport.Posts.Should().BeEmpty();
        transport.ConfigPostCount.Should().Be(0);
        transport.Gets.Should().HaveCount(4);
        transport.Gets.Should().OnlyContain(uri => uri.Contains("192.168.100.1") || uri.StartsWith("/?"));
        transport.Gets.Select(F6201BGetUrl.Identity).Distinct().Should().HaveCount(4);
        result.SessionCookiesPreserved.Should().BeTrue();
        transport.HasSessionCookie.Should().BeTrue();
        typeof(F6201BHomologatedReadCoordinator).Assembly.GetReferencedAssemblies()
            .Should().NotContain(name => name.Name != null && name.Name.Contains("WebView2", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Version_ipv4_is_not_firmware()
    {
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse((
            "/?_type=menuData&_tag=wan_internetstatus_lua.lua&pageType=1&TypeUplink=2",
            "<Instance><ParaName>Version</ParaName><ParaValue>IPv4</ParaValue></Instance>"));
        parsed.SoftwareVersion.Should().BeNull();
        F6201BFirmwareCompatibility.Classify(parsed.SoftwareVersion).Should().Be(FirmwareCompatibility.Unconfirmed);
        F6201BFieldAssociation.IsExactSoftwareFirmwareField("Version").Should().BeFalse();
    }

    [Fact]
    public void Exact_software_version_confirms_and_different_pn_is_incompatible()
    {
        var ok = F6201BV9310P8N1DeviceInformationParser.Parse((
            "/?_type=menuData&_tag=devmgr_statusmgr_lua.lua",
            Fixture("zte-f6201b-v9310p8n1-homologated-device.xml")));
        ok.SoftwareVersion.Should().Be("V9.3.10P8N1");
        F6201BFirmwareCompatibility.Classify(ok.SoftwareVersion).Should().Be(FirmwareCompatibility.ConfirmedCompatible);

        var other = F6201BV9310P8N1DeviceInformationParser.Parse((
            "/?_type=menuData&_tag=devmgr_statusmgr_lua.lua",
            Fixture("zte-f6201b-v9310p8n1-homologated-device.xml").Replace("V9.3.10P8N1", "V9.3.10P9N1")));
        F6201BFirmwareCompatibility.Classify(other.SoftwareVersion).Should().Be(FirmwareCompatibility.ConfirmedIncompatible);
    }

    [Fact]
    public async Task Partial_page_failure_keeps_cookies_and_does_not_duplicate_gets()
    {
        var transport = new HomologatedTransport { FailPon = true };
        var result = await F6201BHomologatedReadCoordinator.ReadAsync(transport, CancellationToken.None);
        result.SessionCookiesPreserved.Should().BeTrue();
        transport.HasSessionCookie.Should().BeTrue();
        transport.LastCleanupReason.Should().BeNull();
        result.FieldReads.Should().Contain(item => item.Field == "ONU State" && item.Status == FieldReadStatus.Partial);
        result.Device.SoftwareVersion.Should().Be("V9.3.10P8N1");
        transport.Gets.Select(F6201BGetUrl.Identity).Distinct().Count().Should().Be(transport.Gets.Count);
        transport.ConfigPostCount.Should().Be(0);
        transport.Posts.Should().BeEmpty();
    }

    [Fact]
    public async Task Incompatible_firmware_stops_remaining_reads()
    {
        var transport = new HomologatedTransport { IncompatibleFirmware = true };
        var result = await F6201BHomologatedReadCoordinator.ReadAsync(transport, CancellationToken.None);
        result.FirmwareCompatibility.Should().Be(FirmwareCompatibility.ConfirmedIncompatible);
        transport.Gets.Should().Contain(uri => uri.Contains("devmgr_statusmgr_lua.lua"));
        transport.Gets.Should().NotContain(uri => uri.Contains("wan_internet_lua.lua"));
        F6201BFirmwareCompatibility.AllowsWrite(result.FirmwareCompatibility).Should().BeFalse();
        transport.HasSessionCookie.Should().BeTrue();
    }

    [Fact]
    public void Masks_mac_serial_loid_user_and_ip()
    {
        var device = F6201BV9310P8N1DeviceInformationParser.Parse((
            "/?_type=menuData&_tag=devmgr_statusmgr_lua.lua",
            Fixture("zte-f6201b-v9310p8n1-homologated-device.xml")));
        var pon = F6201BV9310P8N1PonParser.Parse((
            "/?_type=menuData&_tag=optical_info_lua.lua",
            Fixture("zte-f6201b-v9310p8n1-homologated-pon.xml")));
        var wan = F6201BV9310P8N1WanParser.Parse(
            ("/?_type=menuData&_tag=wan_internetstatus_lua.lua", Fixture("zte-f6201b-v9310p8n1-homologated-wan-status.xml")),
            ("/?_type=menuData&_tag=wan_internet_lua.lua", Fixture("zte-f6201b-v9310p8n1-homologated-wan-config.xml")));

        TantoOntManager.Domain.Audit.SensitiveDataMasker.MaskSerial(device.SerialNumber).Should().NotBe("ZTEG00LAB001");
        TantoOntManager.Domain.Audit.SensitiveDataMasker.MaskMac(device.MacAddress).Should().NotContain("11:22");
        TantoOntManager.Domain.Audit.SensitiveDataMasker.MaskUsername(pon.Loid).Should().NotBe("labloid001");
        wan.Profiles[0].Ipv4Address.Should().Be("100.64.x.x");
        wan.Profiles[0].PppoeUsername.Should().Be("u******p");
        string.Join('\n', wan.Profiles.Select(item => item.Name + item.ServiceList)).Should().NotContain("secret-lab");
    }

    private static void SensitiveDataMaskerShouldHide(HomologatedReadExecution result)
    {
        var serial = result.FieldReads.Single(item => item.Field == "Serial Number").SanitizedValue;
        serial.Should().NotBe("ZTEG00LAB001");
        result.FieldReads.Single(item => item.Field == "MAC Address").SanitizedValue.Should().NotContain("11:22:33");
        result.FieldReads.Single(item => item.Field == "LOID").SanitizedValue.Should().NotBe("labloid001");
        result.Wan.Profiles[0].Ipv4Address.Should().NotBe("100.64.10.25");
        result.Wan.Profiles[0].Dns.Should().Be("8.8.x.x");
        result.Wan.Profiles[0].Gateway.Should().Be("100.64.x.x");
    }

    private sealed class HomologatedTransport : IBoundOntTransport
    {
        public bool FailPon { get; set; }
        public bool IncompatibleFirmware { get; set; }
        public List<string> Gets { get; } = [];
        public List<string> Posts { get; } = [];
        public IPAddress BoundAddress { get; } = IPAddress.Parse("192.168.100.1");
        public string? ObservedCertificateSha256 => "abc";
        public bool HasSessionCookie { get; private set; } = true;
        public int PostCount => Posts.Count;
        public int LoginPostCount => 1;
        public int LogoutPostCount => 0;
        public int ConfigPostCount => 0;
        public string? SessionToken => "tok";
        public string SessionId => "homologated";
        public int HttpClientInstanceId => 3;
        public int CookieCount => HasSessionCookie ? 1 : 0;
        public string? LastCleanupReason { get; private set; }
        public IReadOnlyList<string> HttpMethodsUsed => Gets.Select(_ => "GET").ToList();
        public IReadOnlyList<string> MaskedGetPages => Gets;
        public IReadOnlyList<string> MaskedPosts => Posts;

        public Task<BoundHttpResult> GetAsync(string pathAndQuery, CancellationToken cancellationToken)
        {
            Gets.Add(pathAndQuery);
            pathAndQuery.Should().NotContain("192.168.1.1");
            if (FailPon && pathAndQuery.Contains("optical_info", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(BoundHttpResult.Fail(Error.Create(ErrorCodes.ProbeTimeout, "falha parcial")));
            }

            string body;
            if (pathAndQuery.Contains("devmgr_statusmgr", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-homologated-device.xml");
                if (IncompatibleFirmware)
                {
                    body = body.Replace("V9.3.10P8N1", "V9.3.10P9N1");
                }
            }
            else if (pathAndQuery.Contains("optical_info", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-homologated-pon.xml");
            }
            else if (pathAndQuery.Contains("wan_internetstatus", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-homologated-wan-status.xml");
            }
            else if (pathAndQuery.Contains("wan_internet_lua", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-homologated-wan-config.xml");
            }
            else
            {
                return Task.FromResult(BoundHttpResult.Fail(Error.Create(ErrorCodes.GetNotAllowlisted, "fora do contrato")));
            }

            var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
            return Task.FromResult(new BoundHttpResult(true, 200, body, "text/xml; charset=utf-8", "https://192.168.100.1" + pathAndQuery, 0, hash, TimeSpan.Zero, null));
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
            LastCleanupReason = reason;
            HasSessionCookie = false;
        }

        public void Dispose()
        {
        }
    }
}
