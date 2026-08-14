using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte;
using TantoOntManager.DeviceAdapters.Zte.Parsing;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Detection;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class ZtePublicDetectionScoringTests
{
    [Theory]
    [InlineData("zte-f6201b-public-real.html")]
    [InlineData("zte-f6201b-case.html")]
    [InlineData("zte-f6201b-entities.html")]
    [InlineData("zte-f6201b-whitespace.html")]
    public void Identifies_f6201b_from_public_markers(string fixture)
    {
        var html = Read(fixture);
        var analysis = ZtePublicPageAnalyzer.Analyze(null, null, html);
        analysis.HasConflict.Should().BeFalse();
        analysis.LooksLikeZte.Should().BeTrue();
        analysis.Model.Should().Be(DeviceModelIds.ZteF6201B);
        analysis.Confidence.Should().BeGreaterThanOrEqualTo(0.55);
        analysis.ConfidenceLevel.Should().BeOneOf(DetectionConfidence.High, DetectionConfidence.Medium);
        analysis.Evidence.Should().Contain(item => item.Contains("F6201B", StringComparison.OrdinalIgnoreCase) || item.Contains("ZTE", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Manufacturer_only_does_not_invent_a_model()
    {
        var html = Read("zte-unknown-model.html");
        var analysis = ZtePublicPageAnalyzer.Analyze("ZTE Management", null, html);
        analysis.LooksLikeZte.Should().BeTrue();
        analysis.Model.Should().BeNull();
        analysis.Confidence.Should().BeLessThan(0.55);
        analysis.ConfidenceLevel.Should().Be(DetectionConfidence.Low);
    }

    [Fact]
    public void Unidentified_page_is_insufficient()
    {
        var html = Read("unidentified.html");
        var analysis = ZtePublicPageAnalyzer.Analyze("Home Gateway", null, html);
        analysis.Model.Should().BeNull();
        analysis.ConfidenceLevel.Should().Be(DetectionConfidence.Insufficient);
    }

    [Fact]
    public void Conflicting_models_are_not_identified()
    {
        var html = Read("zte-conflict.html");
        var analysis = ZtePublicPageAnalyzer.Analyze(null, null, html);
        analysis.HasConflict.Should().BeTrue();
        analysis.Model.Should().BeNull();
        analysis.ConfidenceLevel.Should().Be(DetectionConfidence.Conflict);
    }

    [Fact]
    public async Task Adapter_matches_real_public_page()
    {
        var html = Read("zte-f6201b-public-real.html");
        var adapter = new ZteDeviceAdapter(new FakeReader(html, "F6201B"), NullLogger<ZteDeviceAdapter>.Instance);
        var result = await adapter.ProbeAsync(OntEndpoint.Https(IPAddress.Parse("192.168.100.1")), CancellationToken.None);
        result.Matched.Should().BeTrue();
        result.Manufacturer.Should().Be(ManufacturerNames.Zte);
        result.Model.Should().Be(DeviceModelIds.ZteF6201B);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.55);
    }

    [Fact]
    public async Task Adapter_rejects_conflict()
    {
        var html = Read("zte-conflict.html");
        var adapter = new ZteDeviceAdapter(new FakeReader(html, "Gateway"), NullLogger<ZteDeviceAdapter>.Instance);
        var result = await adapter.ProbeAsync(OntEndpoint.Https(IPAddress.Parse("192.168.100.1")), CancellationToken.None);
        result.Matched.Should().BeFalse();
        result.Error!.Code.Should().Be(ErrorCodes.ConflictingEvidence);
    }

    [Fact]
    public async Task Adapter_can_identify_manufacturer_without_model()
    {
        var html = Read("zte-unknown-model.html");
        var adapter = new ZteDeviceAdapter(new FakeReader(html, "ZTE Management"), NullLogger<ZteDeviceAdapter>.Instance);
        var result = await adapter.ProbeAsync(OntEndpoint.Https(IPAddress.Parse("192.168.100.1")), CancellationToken.None);
        result.Matched.Should().BeTrue();
        result.Manufacturer.Should().Be(ManufacturerNames.Zte);
        result.Model.Should().BeNull();
    }

    private static string Read(string name)
        => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

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
            => Task.FromResult<PublicWebDocument?>(new PublicWebDocument(endpoint, 200, _title, "httpd", _body, null, ["GET"]));
    }
}
