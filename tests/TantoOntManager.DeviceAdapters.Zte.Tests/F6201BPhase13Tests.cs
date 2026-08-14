using System.Net;
using FluentAssertions;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Security.Export;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class F6201BSafeReadDiscoveryTests
{
    private static string Home()
        => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-v9310p8n1-authenticated-home.html"));

    [Fact]
    public void Discovers_only_explicit_tags_and_classifies_them()
    {
        var items = F6201BSafeReadDiscovery.Discover(Home());
        items.Select(item => item.Tag).Should().Contain(new[] { "homePage", "devinfo", "ponInfo", "ethWanStatus", "sntp_data" });
        items.Should().NotContain(item => item.Tag.Equals("status_dev_guess", StringComparison.OrdinalIgnoreCase));
        items.Should().Contain(item => item.Tag == "devinfo" && item.Classification == SafeReadClassification.SafeRead);
        items.Should().Contain(item => item.Tag == "reboot" && item.Classification == SafeReadClassification.BlockedPotentialAction);
        items.Should().Contain(item => item.Tag == "accountMgr" && item.Classification == SafeReadClassification.BlockedPotentialAction);
        items.Should().Contain(item => item.Tag == "wanModify" && item.Classification == SafeReadClassification.BlockedPotentialAction);
        items.Should().Contain(item => item.Tag == "wan_apply" && item.Classification == SafeReadClassification.BlockedPotentialAction);
    }

    [Fact]
    public void Does_not_allow_unknown_or_destructive_gets()
    {
        var ip = System.Net.IPAddress.Parse("192.168.100.1");
        var keys = new[] { "menuView:devinfo" };
        F6201BV9310P8N1AuthContract.IsAllowedGet(new Uri("https://192.168.100.1/?_type=menuView&_tag=devinfo"), ip, keys).Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsAllowedGet(new Uri("https://192.168.100.1/?_type=menuView&_tag=unknownPage"), ip, keys).Should().BeFalse();
        F6201BV9310P8N1AuthContract.IsAllowedGet(new Uri("https://192.168.100.1/?_type=menuView&_tag=reboot"), ip, keys).Should().BeFalse();
        F6201BV9310P8N1AuthContract.IsAllowedGet(new Uri("https://192.168.1.1/?_type=menuView&_tag=devinfo"), ip, keys).Should().BeFalse();
    }
}

public sealed class F6201BParserTests
{
    private static string Fixture(string name)
        => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Device_information_reads_real_values_from_table()
    {
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse(("/", Fixture("zte-f6201b-v9310p8n1-device-info.html")));
        parsed.DeviceType.Should().Be("F6201B");
        parsed.HardwareVersion.Should().Be("V9.3.12");
        parsed.SoftwareVersion.Should().Be("V9.3.10P8N1");
        parsed.BootVersion.Should().Be("V9.3.10P10N6");
        parsed.SerialNumber.Should().Be("ZTEG00LAB001");
        parsed.Evidence.Should().NotBeEmpty();
    }

    [Fact]
    public void Device_information_tolerates_entities_and_spaces()
    {
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse(("/", Fixture("zte-f6201b-v9310p8n1-device-info-entities.html")));
        parsed.DeviceType.Should().Be("F6201B");
        parsed.HardwareVersion.Should().Be("V9.3.12");
        parsed.SoftwareVersion.Should().BeNull();
        parsed.Partial.Should().BeTrue();
    }

    [Fact]
    public void Device_information_reads_json_menu_data()
    {
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse(("/menuData", Fixture("zte-f6201b-v9310p8n1-menu-data-devinfo.json")));
        parsed.SoftwareVersion.Should().Be("V9.3.10P8N1");
        parsed.HardwareVersion.Should().Be("V9.3.12");
    }

    [Fact]
    public void Missing_and_altered_html_do_not_invent_known_firmware()
    {
        var missing = F6201BV9310P8N1DeviceInformationParser.Parse(("/", "<html><body>Dashboard</body></html>"));
        missing.SoftwareVersion.Should().BeNull();
        missing.HardwareVersion.Should().BeNull();

        var altered = F6201BV9310P8N1DeviceInformationParser.Parse(("/", "<table><tr><td>Something else</td><td>nope</td></tr></table>"));
        altered.SoftwareVersion.Should().BeNull();
        F6201BV9310P8N1AuthenticatedPageParser.FirmwareMatchesWhenPresent(
            F6201BV9310P8N1AuthenticatedPageParser.ToIdentity("ZTE", "F6201B", missing)).Should().BeTrue();
    }

    [Fact]
    public void Pon_parser_reads_optical_fields()
    {
        var parsed = F6201BV9310P8N1PonParser.Parse(("/", Fixture("zte-f6201b-v9310p8n1-pon.html")));
        parsed.OnuState.Should().Be("O5");
        parsed.InputPower.Should().Contain("-18.12");
        parsed.OutputPower.Should().Contain("2.15");
        parsed.Voltage.Should().Contain("3.28");
        parsed.BiasCurrent.Should().Contain("12.4");
        parsed.Temperature.Should().Contain("41");
    }

    [Fact]
    public void Wan_parser_masks_identifiers_and_omits_pppoe_secrets()
    {
        var parsed = F6201BV9310P8N1WanParser.Parse(("/", Fixture("zte-f6201b-v9310p8n1-wan.json")));
        parsed.Profiles.Should().HaveCount(2);
        parsed.Profiles.Select(item => item.Name).Should().BeEquivalentTo("HSI_TR069", "VOIP_IPTV");
        parsed.Profiles[0].VlanId.Should().Be(210);
        parsed.Profiles[1].VlanId.Should().Be(220);
        parsed.Profiles.Should().OnlyContain(item => item.Ipv4Address != null && item.Ipv4Address.Contains('x'));
        var json = System.Text.Json.JsonSerializer.Serialize(parsed.Profiles);
        json.Should().NotContain("secret-lab");
        json.Should().NotContain("user@isp");
        json.Should().NotContain("00:11:22:33:44:55");
        json.Should().NotContain("100.64.10.25");
    }

    [Fact]
    public void Session_expired_and_login_json_are_detected()
    {
        F6201BHtmlText.LooksLikeSessionExpired(Fixture("zte-f6201b-v9310p8n1-session-expired.json")).Should().BeTrue();
        F6201BHtmlText.LooksLikeLoginInsteadOfInternalPage(Fixture("zte-f6201b-v9310p8n1-session-expired.json")).Should().BeTrue();
        F6201BHtmlText.LooksLikeSessionExpired(Fixture("zte-f6201b-v9310p8n1-device-info.html")).Should().BeFalse();
    }

    [Fact]
    public void Serial_and_mac_masking_keeps_partial_values()
    {
        TantoOntManager.Domain.Audit.SensitiveDataMasker.MaskSerial("ZTEG00LAB001").Should().Be("ZTE******001");
        TantoOntManager.Domain.Audit.SensitiveDataMasker.MaskMac("00:11:22:33:44:55").Should().Be("00:**:**:**:**:55");
    }
}

public sealed class F6201BLogoutTests
{
    [Fact]
    public async Task Successful_logout_posts_once_and_confirms_remote()
    {
        var transport = new LogoutTransport { Body = """{"need_refresh":true}""" };
        var result = await F6201BV9310P8N1Logout.ExecuteAsync(transport, CancellationToken.None);
        result.RemoteInvalidationConfirmed.Should().BeTrue();
        result.Message.Should().Be("Sessão invalidada na ONT");
        result.LogoutPostCount.Should().Be(1);
        result.CookiesDiscarded.Should().BeTrue();
        transport.HasSessionCookie.Should().BeFalse();
        transport.SessionToken.Should().BeNull();
    }

    [Fact]
    public async Task Rejected_logout_still_discards_cookies()
    {
        var transport = new LogoutTransport { Body = """{"need_refresh":false,"loginErrMsg":"This page has expired, please refresh and try again."}""" };
        var result = await F6201BV9310P8N1Logout.ExecuteAsync(transport, CancellationToken.None);
        result.RemoteInvalidationConfirmed.Should().BeFalse();
        result.Message.Should().Be("Sessão local encerrada; invalidação remota não confirmada");
        transport.HasSessionCookie.Should().BeFalse();
    }

    [Fact]
    public async Task Timeout_logout_still_discards_cookies()
    {
        var transport = new LogoutTransport { Timeout = true };
        var result = await F6201BV9310P8N1Logout.ExecuteAsync(transport, CancellationToken.None);
        result.RemoteInvalidationConfirmed.Should().BeFalse();
        result.CookiesDiscarded.Should().BeTrue();
        transport.HasSessionCookie.Should().BeFalse();
    }

    private sealed class LogoutTransport : IBoundOntTransport
    {
        public string Body { get; set; } = "{}";
        public bool Timeout { get; set; }
        public IPAddress BoundAddress { get; } = IPAddress.Parse("192.168.100.1");
        public string? ObservedCertificateSha256 => "abc";
        public bool HasSessionCookie { get; private set; } = true;
        public int PostCount => LoginPostCount + LogoutPostCount;
        public int LoginPostCount => 1;
        public int LogoutPostCount { get; private set; }
        public int ConfigPostCount => 0;
        public string? SessionToken { get; private set; } = "tok2";
        public string SessionId => "logout";
        public int HttpClientInstanceId => 1;
        public int CookieCount => HasSessionCookie ? 1 : 0;
        public string? LastCleanupReason { get; private set; }
        public IReadOnlyList<string> HttpMethodsUsed => ["POST"];
        public IReadOnlyList<string> MaskedGetPages => [];
        public IReadOnlyList<string> MaskedPosts => [];

        public Task<BoundHttpResult> GetAsync(string pathAndQuery, CancellationToken cancellationToken)
            => throw new InvalidOperationException();

        public Task<BoundHttpResult> PostLoginFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
            => throw new InvalidOperationException();

        public Task<BoundHttpResult> PostLogoutFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
        {
            form["IF_LogOff"].Should().Be("1");
            if (Timeout)
            {
                return Task.FromResult(BoundHttpResult.Fail(Error.Create(ErrorCodes.ProbeTimeout, "timeout")));
            }

            LogoutPostCount++;
            return Task.FromResult(new BoundHttpResult(
                true, 200, Body, "application/json", "https://192.168.100.1/?_type=loginData&_tag=logout_entry",
                0, "abcd1234", TimeSpan.FromMilliseconds(3), null));
        }

        public void RememberSafeRead(string type, string tag)
        {
        }

        public void ClearCookiesAndState(string reason)
        {
            LastCleanupReason = reason;
            HasSessionCookie = false;
            SessionToken = null;
        }

        public void Dispose() => ClearCookiesAndState("dispose");
    }
}

public sealed class F6201BAuthenticatedSafeReaderTests
{
    [Fact]
    public async Task Respects_page_limit_and_does_not_loop()
    {
        var tags = string.Join("", Enumerable.Range(1, 20).Select(i => $"<p MenuPage='page{i}'>p{i}</p>"));
        var home = $"<html><body>{tags}</body></html>";
        var transport = new ReaderTransport();
        var homeResult = new BoundHttpResult(true, 200, home, "text/html", "https://192.168.100.1/", 0, "homehash", TimeSpan.Zero, null);
        var result = await F6201BAuthenticatedSafeReader.ReadAsync(transport, home, "/", homeResult, CancellationToken.None);
        result.Pages.Count.Should().BeLessThanOrEqualTo(F6201BV9310P8N1AuthContract.MaxSafeReadPages);
        transport.Gets.Should().NotContain(uri => uri.Contains("unknownGuess"));
        transport.Gets.Distinct().Count().Should().Be(transport.Gets.Count);
    }

    [Fact]
    public async Task Partial_login_like_page_keeps_session()
    {
        var home = "<p MenuPage='devinfo'>Device</p>";
        var transport = new ReaderTransport()
        {
            NextBody = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-v9310p8n1-session-expired.json"))
        };
        var homeResult = new BoundHttpResult(true, 200, home, "text/html", "https://192.168.100.1/", 0, "homehash", TimeSpan.Zero, null);
        var result = await F6201BAuthenticatedSafeReader.ReadAsync(transport, home, "/", homeResult, CancellationToken.None);
        result.SessionExpired.Should().BeFalse();
        result.Pages.Should().HaveCount(1);
        result.Inventory.Should().Contain(item =>
            item.Classification == SafeReadClassification.UnknownNotAccessed);
    }

    private sealed class ReaderTransport : IBoundOntTransport
    {
        public string? NextBody { get; set; }
        public List<string> Gets { get; } = [];
        public IPAddress BoundAddress { get; } = IPAddress.Parse("192.168.100.1");
        public string? ObservedCertificateSha256 => "abc";
        public bool HasSessionCookie => true;
        public int PostCount => 1;
        public int LoginPostCount => 1;
        public int LogoutPostCount => 0;
        public int ConfigPostCount => 0;
        public string? SessionToken => "tok";
        public string SessionId => "reader";
        public int HttpClientInstanceId => 1;
        public int CookieCount => 1;
        public string? LastCleanupReason { get; }
        public IReadOnlyList<string> HttpMethodsUsed => Gets.Select(_ => "GET").ToList();
        public IReadOnlyList<string> MaskedGetPages => Gets;
        public IReadOnlyList<string> MaskedPosts => [];

        public Task<BoundHttpResult> GetAsync(string pathAndQuery, CancellationToken cancellationToken)
        {
            Gets.Add(pathAndQuery);
            var body = NextBody ?? $"<html>{pathAndQuery}</html>";
            var hash = pathAndQuery.GetHashCode().ToString("x8");
            return Task.FromResult(new BoundHttpResult(true, 200, body, "text/html", "https://192.168.100.1" + pathAndQuery, 0, hash, TimeSpan.Zero, null));
        }

        public Task<BoundHttpResult> PostLoginFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
            => throw new InvalidOperationException();

        public Task<BoundHttpResult> PostLogoutFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
            => throw new InvalidOperationException();

        public void RememberSafeRead(string type, string tag)
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

public sealed class AuthenticatedZipInspectorTests
{
    [Fact]
    public void Accepts_sanitized_authenticated_payload()
    {
        var text = AuthenticatedPayloadSanitizer.Sanitize("serial=ZTEG00LAB001 password=lab");
        text.Should().NotContain("lab");
        AuthenticatedPayloadSanitizer.LooksUnsanitized("Set-Cookie: a=b").Should().BeTrue();
    }
}
