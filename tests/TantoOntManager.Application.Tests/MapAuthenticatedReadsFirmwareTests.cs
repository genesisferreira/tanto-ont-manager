using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.Infrastructure.Security;

namespace TantoOntManager.Application.Tests;

public sealed class MapAuthenticatedReadsFirmwareTests
{
    [Fact]
    public async Task Unconfirmed_firmware_keeps_session_and_blocks_writes()
    {
        var transport = new MapTransport
        {
            HomeHtml = "<html><body><a MenuPage='ethWanStatus'>Internet → WAN</a></body></html>",
            WanHtml = "<table><tr><td>Version</td><td>IPv4</td></tr></table>"
        };
        var store = Store(transport, FirmwareCompatibility.Unconfirmed);
        var useCase = new MapAuthenticatedReadsUseCase(store, new SilentAudit(), NullLogger<MapAuthenticatedReadsUseCase>.Instance);

        var result = await useCase.ExecuteAsync(CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        store.State.Should().Be(AuthSessionState.AuthenticatedReadOnly);
        store.DomainSession.Should().NotBeNull();
        store.Snapshot!.FirmwareCompatibility.Should().Be(FirmwareCompatibility.Unconfirmed);
        transport.HasSessionCookie.Should().BeTrue();
        transport.Posts.Should().BeEmpty();
        transport.ConfigPostCount.Should().Be(0);
        transport.LoginPostCount.Should().Be(1);
        transport.Gets.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Confirmed_incompatible_firmware_ends_session_without_config_post()
    {
        var transport = new MapTransport
        {
            HomeHtml = "<html><body><a MenuPage='devStatus'>Device Information</a></body></html>",
            DeviceHtml = """
                         <table>
                           <tr><td>Hardware Version</td><td>V9.3.12</td></tr>
                           <tr><td>Software Version</td><td>V9.3.10P9N1</td></tr>
                         </table>
                         """
        };
        var store = Store(transport, FirmwareCompatibility.Unconfirmed);
        var useCase = new MapAuthenticatedReadsUseCase(store, new SilentAudit(), NullLogger<MapAuthenticatedReadsUseCase>.Instance);

        var result = await useCase.ExecuteAsync(CancellationToken.None);

        result.IsFailure.Should().BeTrue();
        result.Error!.Code.Should().Be(ErrorCodes.ContractIncompatible);
        result.Error.Message.Should().Contain("V9.3.10P9N1");
        result.Error.Message.Should().NotContain("lab-pass");
        store.State.Should().Be(AuthSessionState.ContractIncompatible);
        store.DomainSession.Should().BeNull();
        transport.HasSessionCookie.Should().BeFalse();
        transport.ConfigPostCount.Should().Be(0);
        transport.Posts.Should().BeEmpty();
    }

    private static FakeStore Store(IBoundOntTransport transport, FirmwareCompatibility compatibility)
        => new()
        {
            Transport = transport,
            DomainSession = AuthorizedDeviceSession.Authenticated(
                OntEndpoint.Https(IPAddress.Parse("192.168.100.1")),
                "zte-f6201b-v9.3.10p8n1-json-login",
                "abc"),
            Snapshot = new AuthenticatedReadSnapshot(
                new DeviceIdentity(ManufacturerNames.Zte, DeviceModelIds.ZteF6201B, FirmwareInfo.Unknown, null, null),
                DeviceDiagnostics.PublicInterfaceOnly("aguardando mapa"),
                ["/"],
                1,
                0,
                "200",
                "homehash",
                TimeSpan.Zero,
                "zte-f6201b",
                [],
                [],
                1,
                0,
                0)
            {
                FirmwareCompatibility = compatibility
            },
            State = AuthSessionState.AuthenticatedReadOnly
        };

    private sealed class FakeStore : IOntAuthSessionStore
    {
        public AuthorizedDeviceSession? DomainSession { get; set; }
        public IBoundOntTransport? Transport { get; set; }
        public AuthenticatedReadSnapshot? Snapshot { get; set; }
        public AuthenticatedReadMap? ReadMap { get; set; }
        public AuthSessionState State { get; set; } = AuthSessionState.Unmapped;

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
            Transport = null;
            DomainSession = null;
            Snapshot = null;
            ReadMap = null;
            if (State is AuthSessionState.AuthenticatedReadOnly or AuthSessionState.Authenticating)
            {
                State = AuthSessionState.Unmapped;
            }
        }

        public void SetState(AuthSessionState state) => State = state;

        public bool IsBoundTo(IPAddress address, string? certificateSha256) => true;
    }

    private sealed class SilentAudit : IAuditLogService
    {
        public void Record(AuditEvent auditEvent)
        {
        }
    }

    private sealed class MapTransport : IBoundOntTransport
    {
        public string HomeHtml { get; set; } = "<html><body></body></html>";
        public string DeviceHtml { get; set; } = string.Empty;
        public string WanHtml { get; set; } = string.Empty;
        public List<string> Gets { get; } = [];
        public List<string> Posts { get; } = [];
        public IPAddress BoundAddress { get; } = IPAddress.Parse("192.168.100.1");
        public string? ObservedCertificateSha256 => "abc";
        public bool HasSessionCookie { get; private set; } = true;
        public int PostCount => 1;
        public int LoginPostCount => 1;
        public int LogoutPostCount => 0;
        public int ConfigPostCount => 0;
        public string? SessionToken => "tok";
        public string SessionId => "map-fw";
        public int HttpClientInstanceId => 1;
        public int CookieCount => HasSessionCookie ? 1 : 0;
        public IReadOnlyList<string> HttpMethodsUsed => Gets.Select(_ => "GET").Concat(Posts.Select(_ => "POST")).ToList();
        public IReadOnlyList<string> MaskedGetPages => Gets;
        public IReadOnlyList<string> MaskedPosts => Posts;

        public Task<BoundHttpResult> GetAsync(string pathAndQuery, CancellationToken cancellationToken)
        {
            Gets.Add(pathAndQuery);
            var body = pathAndQuery == "/"
                ? HomeHtml
                : pathAndQuery.Contains("devStatus", StringComparison.OrdinalIgnoreCase)
                    ? DeviceHtml
                    : pathAndQuery.Contains("wan", StringComparison.OrdinalIgnoreCase)
                        ? WanHtml
                        : "<html><body>generic</body></html>";
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

        public void ClearCookiesAndState(string reason) => HasSessionCookie = false;

        public void Dispose()
        {
        }
    }
}
