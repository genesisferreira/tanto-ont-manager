using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging;
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

public sealed class AuthenticatedReadMapTests
{
    private static string Fixture(string name)
        => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Tokenization_does_not_treat_set_inside_offset_as_action()
    {
        F6201BTagSafety.Tokenize("offset").Should().Equal("offset");
        F6201BTagSafety.IsBlocked("offset").Should().BeFalse();
        F6201BTagSafety.IsBlocked("ethWanStatus").Should().BeFalse();
        F6201BTagSafety.IsBlocked("setWan").Should().BeTrue();
        F6201BTagSafety.IsBlocked("accountMgr").Should().BeTrue();
        F6201BTagSafety.IsBlocked("settings").Should().BeTrue();
    }

    [Fact]
    public void Menu_paths_match_priority_screens_without_guessing_tags()
    {
        F6201BPriorityMenu.Match("Management & Diagnosis → Status").Should().Be(F6201BPriorityMenu.DeviceStatus);
        F6201BPriorityMenu.Match("Internet → PON Information").Should().Be(F6201BPriorityMenu.PonInformation);
        F6201BPriorityMenu.Match("Internet → Status → WAN").Should().Be(F6201BPriorityMenu.WanUnderStatus);
        F6201BPriorityMenu.Match("Internet → WAN").Should().Be(F6201BPriorityMenu.Wan);
        F6201BPriorityMenu.Match("Internet → WAN Status").Should().Be(F6201BPriorityMenu.Wan);
        F6201BPriorityMenu.Match("Management → Device Information").Should().BeNull();
    }

    [Fact]
    public void Discovery_keeps_folder_nodes_unfetched_and_maps_menu_text()
    {
        var items = F6201BSafeReadDiscovery.Discover(Fixture("zte-f6201b-v9310p8n1-authenticated-menu-map.html"));
        items.Should().Contain(item => item.Tag == "internet" && item.Classification == SafeReadClassification.UnknownNotAccessed);
        items.Should().Contain(item => item.Tag == "devStatus" && item.MenuText == "Management & Diagnosis → Status");
        items.Should().Contain(item => item.Tag == "ponInfo" && item.Classification == SafeReadClassification.SafeRead);
        items.Should().Contain(item => item.Tag == "offset" && item.Classification == SafeReadClassification.SafeRead);
        items.Should().Contain(item => item.Tag == "accountMgr" && item.Classification == SafeReadClassification.BlockedPotentialAction);
        items.Should().NotContain(item => item.Tag == "status_dev_guess");
    }

    [Fact]
    public void Concatenated_js_patterns_are_recorded_without_inventing_tags()
    {
        var js = Fixture("zte-f6201b-v9310p8n1-common-lib-map.js");
        F6201BUnresolvedPatterns.Find(js).Should().NotBeEmpty();
        var items = F6201BSafeReadDiscovery.Discover(js, "/jquery/common_lib.js");
        items.Should().Contain(item => item.Tag == "devStatus" && item.TypeAndTag.StartsWith("menuData"));
        items.Should().NotContain(item => item.Tag == "ponInfo" && item.TypeAndTag.StartsWith("menuData"));
    }

    [Fact]
    public async Task Mapper_gets_only_evidenced_safe_pages_and_fills_priority_reads()
    {
        var logger = new ListLogger();
        var transport = new MapperTransport();
        var snapshot = EmptySnapshot();
        var result = await F6201BAuthenticatedReadMapper.MapAsync(transport, snapshot, logger, CancellationToken.None);

        transport.Posts.Should().BeEmpty();
        transport.LoginPostCount.Should().Be(1);
        transport.ConfigPostCount.Should().Be(0);
        transport.Gets.Should().Contain("/");
        transport.Gets.Should().Contain("/jquery/common_lib.js");
        transport.Gets.Should().Contain(uri => uri.Contains("_tag=devStatus"));
        transport.Gets.Should().Contain(uri => uri.Contains("_tag=ponInfo"));
        transport.Gets.Should().Contain(uri => uri.Contains("_type=menuData") && uri.Contains("devStatus"));
        transport.Gets.Should().NotContain(uri => uri.Contains("ponInfo") && uri.Contains("menuData"));
        transport.Gets.Should().NotContain(uri => uri.Contains("wanModify"));
        transport.Gets.Should().NotContain(uri => uri.Contains("accountMgr"));
        transport.Gets.Should().NotContain(uri => uri.Contains("wan_apply"));
        transport.Gets.Should().NotContain(uri => uri.Contains("reboot"));

        result.Map.PriorityFound.Should().Contain(F6201BPriorityMenu.DeviceStatus);
        result.Map.PriorityFound.Should().Contain(F6201BPriorityMenu.PonInformation);
        result.Map.PriorityMissing.Should().BeEmpty();
        result.Snapshot.Identity.Firmware.HardwareVersion.Should().Be("V9.3.12");
        result.Snapshot.FirmwareCompatibility.Should().Be(FirmwareCompatibility.ConfirmedCompatible);
        result.Snapshot.Diagnostics.Pon.OnuState.Should().Be("O5");
        result.Snapshot.Diagnostics.WanProfiles.Should().NotBeEmpty();

        var joined = string.Join('\n', logger.Messages);
        joined.Should().Contain("Mapa autenticado type=");
        joined.Should().NotContain("SID_HTTPS_=");
        joined.Should().NotContain("lab-pass");
        joined.Should().NotContain("_sessionTOKEN=tok");
        joined.Should().NotContain("cafebabe");
    }

    [Fact]
    public async Task Mapper_reports_missing_priority_instead_of_guessing()
    {
        var transport = new MapperTransport
        {
            HomeHtml = Fixture("zte-f6201b-v9310p8n1-authenticated-home.html")
        };
        var result = await F6201BAuthenticatedReadMapper.MapAsync(transport, EmptySnapshot(), NullLogger.Instance, CancellationToken.None);
        result.Map.PriorityMissing.Should().Contain(F6201BPriorityMenu.DeviceStatus);
        result.Map.Note.Should().Contain("Nenhum endpoint foi adivinhado");
        result.Snapshot.FirmwareCompatibility.Should().Be(FirmwareCompatibility.Unconfirmed);
        transport.Gets.Should().NotContain(uri => uri.Contains("status_dev_guess"));
    }

    [Fact]
    public async Task Mapper_reads_homepage_shell_then_literal_data_endpoint()
    {
        var transport = new MapperTransport
        {
            HomeHtml = Fixture("zte-f6201b-v9310p8n1-homepage-shell.html")
        };
        var result = await F6201BAuthenticatedReadMapper.MapAsync(transport, EmptySnapshot(), NullLogger.Instance, CancellationToken.None);
        transport.Posts.Should().BeEmpty();
        transport.ConfigPostCount.Should().Be(0);
        transport.Gets.Should().Contain(uri => uri.Contains("firewall_homepage_lua"));
        transport.Gets.Should().Contain(uri => uri.Contains("_type=menuData") && uri.Contains("devStatus"));
        result.Map.Entries.Should().Contain(item => item.Tag == "firewall_homepage_lua" && item.RouteKind == AuthenticatedRouteKind.HomepageShell);
        result.Map.Entries.Should().Contain(item => item.Tag == "devStatus" && item.RouteKind == AuthenticatedRouteKind.DataEndpoint);
        result.Snapshot.Identity.Firmware.HardwareVersion.Should().Be("V9.3.12");
        result.Snapshot.FirmwareCompatibility.Should().Be(FirmwareCompatibility.ConfirmedCompatible);
    }

    [Fact]
    public async Task Mapper_marks_real_different_firmware_incompatible_without_config_post()
    {
        var transport = new MapperTransport
        {
            DeviceInfoHtml = """
                             <table>
                               <tr><td>Hardware Version</td><td>V9.3.12</td></tr>
                               <tr><td>Software Version</td><td>V9.3.10P9N1</td></tr>
                             </table>
                             """
        };
        var result = await F6201BAuthenticatedReadMapper.MapAsync(transport, EmptySnapshot(), NullLogger.Instance, CancellationToken.None);
        result.Snapshot.FirmwareCompatibility.Should().Be(FirmwareCompatibility.ConfirmedIncompatible);
        result.Snapshot.Identity.Firmware.SoftwareVersion.Should().Be("V9.3.10P9N1");
        transport.Posts.Should().BeEmpty();
        transport.ConfigPostCount.Should().Be(0);
        F6201BFirmwareCompatibility.AllowsWrite(result.Snapshot.FirmwareCompatibility).Should().BeFalse();
    }

    [Fact]
    public async Task Mapper_respects_page_limit_and_does_not_post_config()
    {
        var tags = string.Join("", Enumerable.Range(1, 20).Select(i => $"<p MenuPage='page{i}'>p{i}</p>"));
        var transport = new MapperTransport { HomeHtml = $"<html><body>{tags}</body></html>" };
        var result = await F6201BAuthenticatedReadMapper.MapAsync(transport, EmptySnapshot(), NullLogger.Instance, CancellationToken.None);
        result.Snapshot.PagesRead.Count.Should().BeLessThanOrEqualTo(F6201BV9310P8N1AuthContract.MaxSafeReadPages);
        transport.Posts.Should().BeEmpty();
        transport.ConfigPostCount.Should().Be(0);
        transport.Gets.Should().NotContain(uri => uri.Contains("unknownGuess"));
        transport.Gets.Distinct().Count().Should().Be(transport.Gets.Count);
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

    private sealed class MapperTransport : IBoundOntTransport
    {
        public string HomeHtml { get; set; } = Fixture("zte-f6201b-v9310p8n1-authenticated-menu-map.html");
        public string? DeviceInfoHtml { get; set; }
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
        public string SessionId => "map";
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
                body = HomeHtml;
            }
            else if (pathAndQuery.Contains("firewall_homepage_lua", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-homepage-shell-body.html");
            }
            else if (pathAndQuery.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-common-lib-map.js");
            }
            else if (pathAndQuery.Contains("ponInfo", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-pon.html");
            }
            else if (pathAndQuery.Contains("ethWan", StringComparison.OrdinalIgnoreCase))
            {
                body = Fixture("zte-f6201b-v9310p8n1-wan.json");
            }
            else if (pathAndQuery.Contains("devStatus", StringComparison.OrdinalIgnoreCase))
            {
                body = DeviceInfoHtml
                       ?? (pathAndQuery.Contains("menuData", StringComparison.OrdinalIgnoreCase)
                           ? Fixture("zte-f6201b-v9310p8n1-menu-data-devinfo.json")
                           : Fixture("zte-f6201b-v9310p8n1-device-info.html"));
            }
            else
            {
                body = "<html><body>generic</body></html>";
            }

            var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant()[..8];
            return Task.FromResult(new BoundHttpResult(true, 200, body, "text/html", "https://192.168.100.1" + pathAndQuery, 0, hash, TimeSpan.Zero, null));
        }

        public Task<BoundHttpResult> PostLoginFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
        {
            Posts.Add("login");
            return Task.FromResult(BoundHttpResult.Fail(Error.Create(ErrorCodes.PostNotAllowed, "POST recusado no mapa")));
        }

        public Task<BoundHttpResult> PostLogoutFormAsync(IReadOnlyDictionary<string, string> form, CancellationToken cancellationToken)
        {
            Posts.Add("logout");
            return Task.FromResult(BoundHttpResult.Fail(Error.Create(ErrorCodes.PostNotAllowed, "POST recusado no mapa")));
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

    private sealed class ListLogger : ILogger
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Messages.Add(formatter(state, exception));
    }
}
