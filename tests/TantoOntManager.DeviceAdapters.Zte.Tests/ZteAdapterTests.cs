using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte;
using TantoOntManager.DeviceAdapters.Zte.Parsing;
using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class ZtePublicPageAnalyzerTests
{
    [Fact]
    public void Recognizes_f6201b_from_saved_login_page()
    {
        var html = ReadFixture("zte-f6201b-login.html");
        var analysis = ZtePublicPageAnalyzer.Analyze("ZXHN F6201B", null, html);
        analysis.LooksLikeZte.Should().BeTrue();
        analysis.Model.Should().Be(DeviceModelIds.ZteF6201B);
        analysis.Confidence.Should().BeGreaterThanOrEqualTo(0.8);
        analysis.LoginFormVisible.Should().BeTrue();
    }

    [Fact]
    public void Does_not_claim_zte_on_generic_gateway()
    {
        var html = ReadFixture("generic-gateway.html");
        var analysis = ZtePublicPageAnalyzer.Analyze("Home Gateway", "Generic", html);
        analysis.LooksLikeZte.Should().BeFalse();
        analysis.Model.Should().BeNull();
        analysis.Confidence.Should().Be(0);
    }

    [Fact]
    public void Zte_without_model_is_not_enough_for_homologated_match()
    {
        var html = ReadFixture("zte-unknown-model.html");
        var analysis = ZtePublicPageAnalyzer.Analyze("ZTE Management", null, html);
        analysis.LooksLikeZte.Should().BeTrue();
        analysis.Model.Should().BeNull();
        analysis.Confidence.Should().BeLessThan(0.55);
    }

    private static string ReadFixture(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", name);
        return File.ReadAllText(path);
    }
}

public sealed class ZteDeviceAdapterTests
{
    [Fact]
    public async Task Probe_matches_f6201b_public_page()
    {
        var html = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-login.html"));
        var adapter = new ZteDeviceAdapter(new FakeReader(html, "ZXHN F6201B"), NullLogger<ZteDeviceAdapter>.Instance);
        var result = await adapter.ProbeAsync(OntEndpoint.Https(IPAddress.Parse("192.168.100.1")), CancellationToken.None);
        result.Matched.Should().BeTrue();
        result.Model.Should().Be(DeviceModelIds.ZteF6201B);
        result.Manufacturer.Should().Be(ManufacturerNames.Zte);
    }

    [Fact]
    public async Task Probe_rejects_generic_page()
    {
        var html = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "generic-gateway.html"));
        var adapter = new ZteDeviceAdapter(new FakeReader(html, "Home Gateway"), NullLogger<ZteDeviceAdapter>.Instance);
        var result = await adapter.ProbeAsync(OntEndpoint.Http(IPAddress.Parse("192.168.1.1")), CancellationToken.None);
        result.Matched.Should().BeFalse();
        result.Error!.Code.Should().Be(ErrorCodes.InsufficientEvidence);
    }

    [Fact]
    public async Task Authentication_is_not_mapped_and_does_not_invent_endpoints()
    {
        var html = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-login.html"));
        var adapter = new ZteDeviceAdapter(new FakeReader(html, "ZXHN F6201B"), NullLogger<ZteDeviceAdapter>.Instance);
        var probe = AdapterProbeResult.Match(
            ZteDeviceAdapter.Id,
            ManufacturerNames.Zte,
            DeviceModelIds.ZteF6201B,
            0.9,
            OntEndpoint.Https(IPAddress.Parse("192.168.100.1")),
            [],
            true,
            true);

        adapter.CanAttemptAuthentication(probe).Should().BeFalse();
        using var password = new System.Security.SecureString();
        password.AppendChar('x');
        using var credentials = new DeviceCredentials("user", password.Copy(), false);
        var auth = await adapter.AuthenticateAsync(probe.Endpoint, probe, credentials, CancellationToken.None);
        auth.Outcome.Should().Be(AuthenticationOutcome.MethodNotMapped);
        auth.Error!.Code.Should().Be(ErrorCodes.AuthenticationMethodNotMapped);
    }

    [Fact]
    public async Task Public_diagnostics_do_not_invent_wan_or_pon_values()
    {
        var html = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-login.html"));
        var adapter = new ZteDeviceAdapter(new FakeReader(html, "ZXHN F6201B"), NullLogger<ZteDeviceAdapter>.Instance);
        var session = AuthorizedDeviceSession.Public(OntEndpoint.Https(IPAddress.Parse("192.168.100.1")));
        var diagnostics = await adapter.ReadDiagnosticsAsync(session, CancellationToken.None);
        diagnostics.Succeeded.Should().BeTrue();
        diagnostics.Diagnostics!.WanProfiles.Should().BeEmpty();
        diagnostics.Diagnostics.Pon.OnuState.Should().BeNull();
        diagnostics.Diagnostics.SourceIsPublicInterface.Should().BeTrue();
    }

    private sealed class FakeReader : IPublicWebReader
    {
        private readonly string _body;
        private readonly string _title;

        public FakeReader(string body, string title)
        {
            _body = body;
            _title = title;
        }

        public Task<PublicWebDocument?> GetRootAsync(OntEndpoint endpoint, CancellationToken cancellationToken)
            => Task.FromResult<PublicWebDocument?>(new PublicWebDocument(endpoint, 200, _title, "httpd", _body));
    }
}
