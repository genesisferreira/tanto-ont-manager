using System.Net;
using System.Security;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class F6201BAuthContractTests
{
    [Fact]
    public void Recognizes_exact_login_contract_from_real_markers()
    {
        var html = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-v9310p8n1-login-contract.html"));
        F6201BV9310P8N1AuthContract.PublicPageMatchesContract(html).Should().BeTrue();
        html.Should().Contain("/?_type=loginData&_tag=login_entry");
        html.Should().Contain("/?_type=loginData&_tag=login_token");
        html.Should().Contain("postData[\"action\"] = \"login\"");
        html.Should().Contain("sha256(Password+xmlObj)");
        html.Should().Contain("login_need_refresh");
        html.Should().NotContain("admin");
        html.Should().NotContain("password123");
    }

    [Fact]
    public void Hash_matches_sha256_of_password_plus_challenge()
    {
        var hash = F6201BV9310P8N1LoginParser.HashPassword("lab-pass", "cafebabe");
        hash.Should().Be("b3e0da3a4a58e2b3c1fd18d8c762aed9ace8434e4c825ac5227179aa17d0cb4a");
        hash.Should().NotContain("lab-pass");
    }
}

public sealed class ZteF6201BV9310P8N1AuthenticationAdapterTests
{
    private readonly OntEndpoint _endpoint = OntEndpoint.Https(IPAddress.Parse("192.168.100.1"));

    [Fact]
    public void Can_attempt_only_for_detected_f6201b()
    {
        var adapter = Create(new FakeTransport());
        adapter.CanAttemptAuthentication(Probe()).Should().BeTrue();
        adapter.CanAttemptAuthentication(Probe(model: DeviceModelIds.ZteF6600P)).Should().BeFalse();
    }

    [Fact]
    public async Task Successful_login_posts_once_and_reads_allowlisted_pages()
    {
        var transport = SuccessfulTransport();
        var store = new FakeStore();
        var adapter = Create(transport, store);
        using var credentials = Creds("lab-user", "lab-pass");

        var result = await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, "abc123", CancellationToken.None);

        result.Outcome.Should().Be(AuthenticationOutcome.Succeeded);
        result.SessionState.Should().Be(AuthSessionState.AuthenticatedReadOnly);
        result.PostCount.Should().Be(1);
        transport.Posts.Should().HaveCount(1);
        transport.Posts[0].Should().Contain("_tag=login_entry");
        transport.Gets.Should().Contain("/");
        transport.Gets.Should().Contain(uri => uri.Contains("statusMgr"));
        transport.Gets.Should().Contain(uri => uri.Contains("devmgr_statusmgr_lua.lua"));
        transport.Gets.Should().Contain(uri => uri.Contains("optical_info_lua.lua"));
        transport.Gets.Should().Contain(uri => uri.Contains("wan_internetstatus_lua.lua"));
        transport.Gets.Should().Contain(uri => uri.Contains("wan_internet_lua.lua"));
        transport.Gets.Should().NotContain(uri => uri.Contains("reboot"));
        store.Snapshot.Should().NotBeNull();
        store.Snapshot!.Identity.Firmware.SoftwareVersion.Should().Be("V9.3.10P8N1");
        store.Snapshot.FirmwareCompatibility.Should().Be(FirmwareCompatibility.ConfirmedCompatible);
        F6201BFirmwareCompatibility.AllowsWrite(store.Snapshot.FirmwareCompatibility).Should().BeFalse();
        store.Snapshot.FirmwareCompatibility.ToAuthenticatedUiLabel().Should().Be("Autenticado — somente leitura");
        store.Snapshot.LoginPostCount.Should().Be(1);
        store.Snapshot.ConfigPostCount.Should().Be(0);
        store.Snapshot.LogoutPostCount.Should().Be(0);
        transport.Gets.Should().NotContain(uri => uri.Contains("reboot"));
        transport.Gets.Should().NotContain(uri => uri.Contains("account"));
        transport.Gets.Should().NotContain(uri => uri.Contains("192.168.1.1"));
        transport.Posts.Should().HaveCount(1);
        store.Transport!.HasSessionCookie.Should().BeTrue();
        result.PagesRead.Should().NotBeEmpty();
        transport.LastCleanupReason.Should().BeNull();
    }

    [Fact]
    public async Task Rejected_credential_does_not_retry()
    {
        var transport = SuccessfulTransport();
        transport.PostBody = """{"login_need_refresh":false,"loginErrMsg":"Login failed","promptMsg":"","lockingTime":0}""";
        var adapter = Create(transport);
        using var credentials = Creds("lab-user", "lab-pass");

        var result = await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, null, CancellationToken.None);

        result.SessionState.Should().Be(AuthSessionState.CredentialRejected);
        result.Error!.Code.Should().Be(ErrorCodes.CredentialRejected);
        transport.Posts.Should().HaveCount(1);
        result.Error.Message.Should().NotContain("user");
        result.Error.Message.Should().NotContain("senha incorreta");
    }

    [Fact]
    public async Task Missing_token_does_not_post()
    {
        var transport = SuccessfulTransport();
        transport.BootstrapJson = """{"loginErrMsg":"","promptMsg":"","lockingTime":0}""";
        var adapter = Create(transport);
        using var credentials = Creds("lab-user", "lab-pass");

        var result = await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, null, CancellationToken.None);

        result.Error!.Code.Should().Be(ErrorCodes.AuthTokenMissing);
        transport.Posts.Should().BeEmpty();
    }

    [Fact]
    public async Task Expired_token_is_typed_and_not_retried()
    {
        var transport = SuccessfulTransport();
        transport.PostBody = """{"login_need_refresh":false,"loginErrMsg":"This page has expired, please refresh and try again.","promptMsg":"","lockingTime":0}""";
        var adapter = Create(transport);
        using var credentials = Creds("lab-user", "lab-pass");

        var result = await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, null, CancellationToken.None);

        result.Error!.Code.Should().Be(ErrorCodes.AuthTokenExpired);
        transport.Posts.Should().HaveCount(1);
    }

    [Fact]
    public async Task Incompatible_contract_does_not_post()
    {
        var transport = SuccessfulTransport();
        transport.PublicHtml = "<html><title>F6201B</title><body>Welcome</body></html>";
        var adapter = Create(transport);
        using var credentials = Creds("lab-user", "lab-pass");

        var result = await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, null, CancellationToken.None);

        result.SessionState.Should().Be(AuthSessionState.ContractIncompatible);
        transport.Posts.Should().BeEmpty();
    }

    [Fact]
    public async Task Session_clear_drops_in_memory_cookies()
    {
        var transport = SuccessfulTransport();
        var store = new FakeStore();
        var adapter = Create(transport, store);
        using var credentials = Creds("lab-user", "lab-pass");
        await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, null, CancellationToken.None);
        store.Transport!.HasSessionCookie.Should().BeTrue();
        store.End("test");
        store.Transport.Should().BeNull();
        transport.HasSessionCookie.Should().BeFalse();
    }

    [Fact]
    public async Task Unknown_or_missing_firmware_stays_unconfirmed_and_keeps_readonly_session()
    {
        var transport = SuccessfulTransport();
        transport.DeviceHtml = string.Empty;
        transport.WanHtml = "<table><tr><td>Version</td><td>IPv4</td></tr><tr><td>Status</td><td>Connected</td></tr></table>";
        var store = new FakeStore();
        var logger = new ListLogger<ZteF6201BV9310P8N1AuthenticationAdapter>();
        var adapter = new ZteF6201BV9310P8N1AuthenticationAdapter(new FakeFactory(transport), store, logger);
        using var credentials = Creds("lab-user", "lab-pass");

        var result = await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, "abc123", CancellationToken.None);

        result.Outcome.Should().Be(AuthenticationOutcome.Succeeded);
        result.SessionState.Should().Be(AuthSessionState.AuthenticatedReadOnly);
        result.Error.Should().BeNull();
        store.Snapshot.Should().NotBeNull();
        store.Snapshot!.FirmwareCompatibility.Should().Be(FirmwareCompatibility.Unconfirmed);
        store.Snapshot.Identity.Firmware.SoftwareVersion.Should().BeNull();
        store.Snapshot.FirmwareCompatibility.ToAuthenticatedUiLabel()
            .Should().Be(FirmwareCompatibilityDisplay.AuthenticatedUnconfirmed);
        F6201BFirmwareCompatibility.AllowsAuthenticationAndSafeRead(store.Snapshot.FirmwareCompatibility).Should().BeTrue();
        F6201BFirmwareCompatibility.AllowsWrite(store.Snapshot.FirmwareCompatibility).Should().BeFalse();
        transport.LoginPostCount.Should().Be(1);
        transport.ConfigPostCount.Should().Be(0);
        transport.Posts.Should().HaveCount(1);
        transport.Posts[0].Should().Contain("login_entry");
        transport.Gets.Should().NotBeEmpty();
        transport.HttpMethodsUsed.Where(method => method == "POST").Should().HaveCount(1);
        transport.HttpMethodsUsed.Should().Contain("GET");
        store.Transport!.HasSessionCookie.Should().BeTrue();
        transport.LastCleanupReason.Should().BeNull();
        var logs = string.Join('\n', logger.Messages);
        logs.Should().NotContain("lab-pass");
        logs.Should().NotContain("lab-user");
        logs.Should().NotContain("SID_HTTPS_");
        logs.Should().NotContain("_sessionTOKEN");
        logs.Should().NotContain("cafebabe");
    }

    [Fact]
    public async Task Real_ont_regression_wan_version_without_device_page_is_not_incompatible()
    {
        var transport = SuccessfulTransport();
        transport.AuthenticatedHtml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-v9310p8n1-login-contract.html"))
            + "<script>var menuTreeJSON = [{\"id\":\"internet\",\"name\":\"Internet\",\"children\":[{\"id\":\"ethWanStatus\",\"name\":\"WAN\"}]}]; var _sessionTmpToken = \"tok2\";</script>";
        transport.DeviceHtml = string.Empty;
        transport.WanHtml = "<table><tr><td>Version</td><td>IPv4</td></tr><tr><td>Connection Status</td><td>Disconnected</td></tr></table>";
        var store = new FakeStore();
        var adapter = Create(transport, store);
        using var credentials = Creds("lab-user", "lab-pass");

        var result = await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, "abc123", CancellationToken.None);

        result.Outcome.Should().Be(AuthenticationOutcome.Succeeded);
        result.SessionState.Should().Be(AuthSessionState.AuthenticatedReadOnly);
        result.SessionState.Should().NotBe(AuthSessionState.ContractIncompatible);
        store.Snapshot!.FirmwareCompatibility.Should().Be(FirmwareCompatibility.Unconfirmed);
        store.Snapshot.Identity.Firmware.SoftwareVersion.Should().BeNull();
        transport.LastCleanupReason.Should().BeNull();
        store.Transport!.HasSessionCookie.Should().BeTrue();
        transport.LoginPostCount.Should().Be(1);
        transport.ConfigPostCount.Should().Be(0);
        result.Error?.Message.Should().BeNull();
    }

    [Fact]
    public async Task Normalized_homologated_firmware_is_confirmed_compatible()
    {
        var transport = SuccessfulTransport();
        transport.DeviceHtml = "Hardware Version: V9.3.12 Software Version: v9.3.10 p8n1 Boot Version: V9.3.10P10N6";
        var store = new FakeStore();
        var adapter = Create(transport, store);
        using var credentials = Creds("lab-user", "lab-pass");

        var result = await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, null, CancellationToken.None);

        result.Outcome.Should().Be(AuthenticationOutcome.Succeeded);
        store.Snapshot!.FirmwareCompatibility.Should().Be(FirmwareCompatibility.ConfirmedCompatible);
        store.Transport!.HasSessionCookie.Should().BeTrue();
        transport.ConfigPostCount.Should().Be(0);
    }

    [Fact]
    public async Task Real_different_firmware_ends_session_as_incompatible()
    {
        var transport = SuccessfulTransport();
        transport.DeviceHtml = "Hardware Version: V9.3.12 Software Version: V9.3.10P9N1 Boot Version: V9.3.10P10N6";
        var store = new FakeStore();
        var adapter = Create(transport, store);
        using var credentials = Creds("lab-user", "lab-pass");

        var result = await adapter.AuthenticateAsync(_endpoint, Probe(), credentials, "abc123", CancellationToken.None);

        result.Outcome.Should().Be(AuthenticationOutcome.Failed);
        result.SessionState.Should().Be(AuthSessionState.ContractIncompatible);
        result.Error!.Code.Should().Be(ErrorCodes.ContractIncompatible);
        result.Error.Message.Should().Contain("V9.3.10P9N1");
        result.Error.Message.Should().NotContain("lab-pass");
        result.Error.Message.Should().NotContain("cafebabe");
        store.DomainSession.Should().BeNull();
        store.Snapshot.Should().BeNull();
        transport.HasSessionCookie.Should().BeFalse();
        transport.LastCleanupReason.Should().NotBeNull();
        transport.LoginPostCount.Should().Be(1);
        transport.ConfigPostCount.Should().Be(0);
        F6201BFirmwareCompatibility.AllowsWrite(FirmwareCompatibility.ConfirmedIncompatible).Should().BeFalse();
    }

    [Fact]
    public void Destructive_tags_are_blocked()
    {
        F6201BV9310P8N1AuthContract.IsDestructiveTag("reboot").Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsDestructiveTag("factoryReset").Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsDestructiveTag("accountMgr").Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsDestructiveTag("wan_apply").Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsDestructiveTag("wanModify").Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsDestructiveTag("setWan").Should().BeTrue();
        F6201BV9310P8N1AuthContract.IsDestructiveTag("offset").Should().BeFalse();
        F6201BV9310P8N1AuthContract.IsDestructiveTag("ethWanStatus").Should().BeFalse();
        F6201BV9310P8N1AuthContract.IsDestructiveTag("assetInfo").Should().BeFalse();
        F6201BV9310P8N1AuthContract.IsDestructiveTag("dataset").Should().BeFalse();
    }

    [Fact]
    public void No_hardcoded_credentials_in_adapter_sources()
    {
        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src"));
        var files = Directory.GetFiles(root, "*.cs", SearchOption.AllDirectories);
        foreach (var file in files)
        {
            var text = File.ReadAllText(file);
            text.Should().NotContain("admin/admin");
            text.Should().NotContain("user/user");
            text.Should().NotContain("password123");
            text.Should().NotContain("Frm_Password\" value=\"");
        }
    }

    private ZteF6201BV9310P8N1AuthenticationAdapter Create(FakeTransport transport, FakeStore? store = null)
        => new(new FakeFactory(transport), store ?? new FakeStore(), NullLogger<ZteF6201BV9310P8N1AuthenticationAdapter>.Instance);

    private AdapterProbeResult Probe(string? model = null)
        => AdapterProbeResult.Match(
            ZteDeviceAdapter.Id,
            ManufacturerNames.Zte,
            model ?? DeviceModelIds.ZteF6201B,
            0.9,
            _endpoint,
            [],
            true,
            true);

    private static DeviceCredentials Creds(string user, string pass)
    {
        var secret = new SecureString();
        foreach (var ch in pass)
        {
            secret.AppendChar(ch);
        }

        secret.MakeReadOnly();
        return new DeviceCredentials(user, secret, false);
    }

    private FakeTransport SuccessfulTransport()
    {
        var html = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-v9310p8n1-login-contract.html"));
        return new FakeTransport
        {
            PublicHtml = html,
            AuthenticatedHtml = html + "<a MenuPage='devinfo'>Device Information</a><a MenuPage='reboot'>Reboot</a><script>var menuTreeJSON = [{\"id\":\"homePage\",\"name\":\"Home\",\"area\":[{\"area\":\"home_t.lp\"}]},{\"id\":\"internet\",\"name\":\"Internet\",\"children\":[{\"id\":\"ponInfo\",\"name\":\"PON Information\"},{\"id\":\"ethWanStatus\",\"name\":\"WAN Status\"}]}]; var _sessionTmpToken = \"tok2\";</script>",
            DeviceHtml = "Hardware Version: V9.3.12 Software Version: V9.3.10P8N1 Boot Version: V9.3.10P10N6 ONU State: O1 Temperature: 41 Tx Power: 2.1 Rx Power: -18.0 WAN Name: HSI_TR069 VLAN: 210 Status: Disconnected Service: INTERNET_TR069"
        };
    }

    private sealed class FakeFactory : IBoundOntTransportFactory
    {
        private readonly IBoundOntTransport _transport;
        public FakeFactory(IBoundOntTransport transport) => _transport = transport;
        public IBoundOntTransport Create(OntEndpoint endpoint, string? pinnedCertificateSha256) => _transport;
    }

    private sealed class FakeStore : IOntAuthSessionStore
    {
        public AuthorizedDeviceSession? DomainSession { get; private set; }
        public IBoundOntTransport? Transport { get; private set; }
        public AuthenticatedReadSnapshot? Snapshot { get; private set; }
        public AuthenticatedReadMap? ReadMap { get; private set; }
        public AuthSessionState State { get; private set; } = AuthSessionState.Unmapped;

        public void Remember(IBoundOntTransport transport, AuthorizedDeviceSession session, AuthenticatedReadSnapshot snapshot)
        {
            Transport = transport;
            DomainSession = session;
            Snapshot = snapshot;
            State = AuthSessionState.AuthenticatedReadOnly;
        }

        public void RememberReadMap(AuthenticatedReadMap map) => ReadMap = map;

        public void ReplaceSnapshot(AuthenticatedReadSnapshot snapshot) => Snapshot = snapshot;

        public void End(string reason)
        {
            Transport?.ClearCookiesAndState(reason);
            Transport?.Dispose();
            Transport = null;
            DomainSession = null;
            Snapshot = null;
            State = AuthSessionState.Unmapped;
        }

        public void SetState(AuthSessionState state) => State = state;

        public bool IsBoundTo(IPAddress address, string? certificateSha256)
            => DomainSession?.IsBoundTo(address, certificateSha256) == true;
    }

    private sealed class FakeTransport : IBoundOntTransport
    {
        public string PublicHtml { get; set; } = string.Empty;
        public string AuthenticatedHtml { get; set; } = string.Empty;
        public string DeviceHtml { get; set; } = string.Empty;
        public string? WanHtml { get; set; }
        public string BootstrapJson { get; set; } = """{"sess_token":"tok","loginErrMsg":"","promptMsg":"","lockingTime":0}""";
        public string ChallengeXml { get; set; } = "<ajax_response_xml_root>cafebabe</ajax_response_xml_root>";
        public string PostBody { get; set; } = """{"login_need_refresh":true,"sess_token":"tok2","loginErrMsg":"","promptMsg":"","lockingTime":0}""";
        public List<string> Gets { get; } = [];
        public List<string> Posts { get; } = [];
        private bool _loggedIn;
        private bool _cookie;

        public IPAddress BoundAddress { get; } = IPAddress.Parse("192.168.100.1");
        public string? ObservedCertificateSha256 { get; private set; }
        public bool HasSessionCookie => _cookie;
        public int PostCount => Posts.Count;
        public int LoginPostCount => Posts.Count(item => item.Contains("login_entry"));
        public int LogoutPostCount => Posts.Count(item => item.Contains("logout_entry"));
        public int ConfigPostCount => 0;
        public string? SessionToken { get; private set; } = "tok";
        public string SessionId => "testsess";
        public int HttpClientInstanceId => 7;
        public int CookieCount => _cookie ? 1 : 0;
        public string? LastCleanupReason { get; private set; }
        public IReadOnlyList<string> HttpMethodsUsed => Gets.Select(_ => "GET").Concat(Posts.Select(_ => "POST")).ToList();
        public IReadOnlyList<string> MaskedGetPages => Gets;
        public IReadOnlyList<string> MaskedPosts => Posts;
        public string LogoutBody { get; set; } = """{"need_refresh":true}""";
        public bool LogoutTimesOut { get; set; }
        public bool LogoutFails { get; set; }

        public Task<BoundHttpResult> GetAsync(string pathAndQuery, CancellationToken cancellationToken)
        {
            Gets.Add(pathAndQuery);
            if (pathAndQuery.Contains("reboot", StringComparison.OrdinalIgnoreCase)
                || pathAndQuery.Contains("account", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(BoundHttpResult.Fail(Error.Create(ErrorCodes.GetNotAllowlisted, "bloqueado")));
            }

            if (pathAndQuery.Contains("_type=menuView", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(Ok("<html><body>template</body></html>", pathAndQuery));
            }

            string body;
            if (pathAndQuery.Contains("login_entry"))
            {
                body = BootstrapJson;
            }
            else if (pathAndQuery.Contains("login_token"))
            {
                body = ChallengeXml;
            }
            else if (pathAndQuery.Contains("wan_internet", StringComparison.OrdinalIgnoreCase)
                     || pathAndQuery.Contains("_tag=wan", StringComparison.OrdinalIgnoreCase))
            {
                body = WrapXml(WanHtml ?? DeviceHtml, "ID_WAN_COMFIG", "WANCName", "HSI_TR069");
            }
            else if (pathAndQuery.Contains("devmgr_statusmgr", StringComparison.OrdinalIgnoreCase)
                     || pathAndQuery.Contains("optical_info", StringComparison.OrdinalIgnoreCase)
                     || pathAndQuery.Contains("devinfo", StringComparison.OrdinalIgnoreCase)
                     || pathAndQuery.Contains("homePage", StringComparison.OrdinalIgnoreCase)
                     || pathAndQuery.Contains("pon", StringComparison.OrdinalIgnoreCase))
            {
                body = pathAndQuery.Contains("optical_info", StringComparison.OrdinalIgnoreCase)
                    ? WrapXml(DeviceHtml, "OBJ_PON_OPTICALPARA_ID", "ONU State", "Initial State(o1)")
                    : WrapXml(DeviceHtml, "OBJ_DEVINFO_ID", "Software Version", ReadColon(DeviceHtml, "Software Version") ?? "V9.3.10P8N1");
            }
            else
            {
                body = _loggedIn ? AuthenticatedHtml : PublicHtml;
            }

            return Task.FromResult(Ok(body, pathAndQuery));
        }

        public Task<BoundHttpResult> PostLoginFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
        {
            form.Should().ContainKey("action");
            form["action"].Should().Be("login");
            form.Should().ContainKey("Username");
            form["Password"].Should().Be(F6201BV9310P8N1LoginParser.HashPassword("lab-pass", "cafebabe"));
            form["Password"].Should().NotBe("lab-pass");
            form.Should().ContainKey("_sessionTOKEN");
            Posts.Add("/?_type=loginData&_tag=login_entry");
            _loggedIn = PostBody.Contains("login_need_refresh\":true", StringComparison.Ordinal);
            _cookie = _loggedIn;
            SessionToken = "tok2";
            return Task.FromResult(Ok(PostBody, "/?_type=loginData&_tag=login_entry"));
        }

        public Task<BoundHttpResult> PostLogoutFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
        {
            form.Should().ContainKey("IF_LogOff");
            form["IF_LogOff"].Should().Be("1");
            form.Should().ContainKey("_sessionTOKEN");
            if (LogoutTimesOut)
            {
                return Task.FromResult(BoundHttpResult.Fail(Error.Create(ErrorCodes.ProbeTimeout, "timeout")));
            }

            Posts.Add("/?_type=loginData&_tag=logout_entry");
            if (LogoutFails)
            {
                return Task.FromResult(Ok("""{"need_refresh":false,"loginErrMsg":"This page has expired, please refresh and try again."}""", "/?_type=loginData&_tag=logout_entry"));
            }

            return Task.FromResult(Ok(LogoutBody, "/?_type=loginData&_tag=logout_entry"));
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
            _cookie = false;
            SessionToken = null;
        }

        public void Dispose() => ClearCookiesAndState("dispose");

        private static string WrapXml(string source, string objectId, string fallbackName, string fallbackValue)
        {
            if (string.IsNullOrWhiteSpace(source))
            {
                return "<?xml version=\"1.0\"?><ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR><IF_ERRORID>0</IF_ERRORID></ajax_response_xml_root>";
            }

            if (source.Contains("ParaName", StringComparison.OrdinalIgnoreCase)
                && source.Contains(objectId, StringComparison.OrdinalIgnoreCase))
            {
                return source;
            }

            var software = ReadColon(source, "Software Version") ?? fallbackValue;
            var hardware = ReadColon(source, "Hardware Version") ?? "V9.3.12";
            var boot = ReadColon(source, "Boot Version") ?? "V9.3.10P10N6";
            if (objectId == "OBJ_DEVINFO_ID")
            {
                return "<ajax_response_xml_root><OBJ_DEVINFO_ID><Instance>"
                       + "<ParaName>Device Type</ParaName><ParaValue>F6201B</ParaValue>"
                       + "<ParaName>Hardware Version</ParaName><ParaValue>" + hardware + "</ParaValue>"
                       + "<ParaName>Software Version</ParaName><ParaValue>" + software + "</ParaValue>"
                       + "<ParaName>Boot Version</ParaName><ParaValue>" + boot + "</ParaValue>"
                       + "</Instance></OBJ_DEVINFO_ID></ajax_response_xml_root>";
            }

            if (objectId == "OBJ_PON_OPTICALPARA_ID")
            {
                return "<ajax_response_xml_root><OBJ_PON_OPTICALPARA_ID><Instance>"
                       + "<ParaName>ONU State</ParaName><ParaValue>Initial State(o1)</ParaValue>"
                       + "<ParaName>Input Power</ParaName><ParaValue>--</ParaValue>"
                       + "<ParaName>Output Power</ParaName><ParaValue>--</ParaValue>"
                       + "</Instance></OBJ_PON_OPTICALPARA_ID></ajax_response_xml_root>";
            }

            return "<ajax_response_xml_root><ID_WAN_COMFIG><Instance>"
                   + "<ParaName>WANCName</ParaName><ParaValue>HSI_TR069</ParaValue>"
                   + "<ParaName>VLANID</ParaName><ParaValue>210</ParaValue>"
                   + "</Instance></ID_WAN_COMFIG></ajax_response_xml_root>";
        }

        private static string? ReadColon(string text, string label)
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                text,
                System.Text.RegularExpressions.Regex.Escape(label) + @":\s*(.+?)(?=\s+(?:Hardware|Software|Boot|ONU|Temperature|Tx|Rx|WAN|VLAN|Status|Service)\b|$)");
            return match.Success ? match.Groups[1].Value.Trim() : null;
        }

        private static BoundHttpResult Ok(string body, string uri)
        {
            var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant()[..8];
            return new(true, 200, body, "text/html", "https://192.168.100.1" + uri, 0, hash, TimeSpan.FromMilliseconds(5), null);
        }
    }

    private sealed class ListLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Messages.Add(formatter(state, exception));
    }
}
