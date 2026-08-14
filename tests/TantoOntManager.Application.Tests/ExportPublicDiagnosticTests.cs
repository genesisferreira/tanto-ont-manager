using System.IO.Compression;
using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Network;
using TantoOntManager.Infrastructure.DependencyInjection;
using TantoOntManager.Infrastructure.Export;
using TantoOntManager.Networking.Probing;

namespace TantoOntManager.Application.Tests;

public sealed class ExportPublicDiagnosticTests
{
    [Fact]
    public async Task Export_zip_excludes_cookies_and_credentials()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-ont-export-" + Guid.NewGuid().ToString("N"));
        var cache = new PublicProbeCache();
        var html = "<html><title>F6201B</title><body>Welcome to F6201B. ZTE Corporation</body></html>";
        var endpoint = OntEndpoint.Https(IPAddress.Parse("192.168.100.1"));
        var observation = new HttpPublicObservation(
            "192.168.100.1",
            "https",
            443,
            "GET",
            200,
            "https://192.168.100.1/",
            0,
            "text/html",
            "utf-8",
            Encoding.UTF8.GetByteCount(html),
            "F6201B",
            "abc123def456",
            TimeSpan.FromMilliseconds(10),
            TimeSpan.FromMilliseconds(20),
            false,
            CertificateObservation.None,
            false,
            "utf-8",
            ["Content-Type: text/html"],
            [],
            ["GET"]);
        cache.Remember(new PublicWebDocument(endpoint, 200, "F6201B", null, html, observation, ["GET"]), observation);

        var useCase = new ExportPublicDiagnosticUseCase(
            cache,
            new LoggingPaths(root),
            new SilentAudit(),
            NullLogger<ExportPublicDiagnosticUseCase>.Instance);

        var result = await useCase.ExecuteAsync(new ExportPublicDiagnosticCommand("operador", "senha-super-secreta"), CancellationToken.None);
        result.IsSuccess.Should().BeTrue();
        File.Exists(result.Value).Should().BeTrue();

        using var zip = ZipFile.OpenRead(result.Value!);
        zip.Entries.Select(entry => entry.Name).Should().BeEquivalentTo(
            "manifest.json",
            "public-response.html",
            "public-response.sha256",
            "certificate.json",
            "diagnostic-summary.txt");

        var combined = string.Join(Environment.NewLine, zip.Entries.Select(ReadEntry));
        combined.Should().NotContain("senha-super-secreta");
        combined.Should().NotContain("Set-Cookie");
        combined.Should().NotContain("Cookie:");
        combined.Should().Contain("GET");
        combined.Should().NotContain("POST");
    }

    [Fact]
    public async Task Export_is_blocked_when_password_leaks_into_html()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-ont-export-" + Guid.NewGuid().ToString("N"));
        var cache = new PublicProbeCache();
        var html = "<html><body>senha-super-secreta</body></html>";
        var endpoint = OntEndpoint.Https(IPAddress.Parse("192.168.100.1"));
        cache.Remember(new PublicWebDocument(endpoint, 200, null, null, html, null, ["GET"]), null);

        var useCase = new ExportPublicDiagnosticUseCase(
            cache,
            new LoggingPaths(root),
            new SilentAudit(),
            NullLogger<ExportPublicDiagnosticUseCase>.Instance);

        var result = await useCase.ExecuteAsync(new ExportPublicDiagnosticCommand(null, "senha-super-secreta"), CancellationToken.None);
        result.IsFailure.Should().BeTrue();
        result.Error!.Code.Should().Be(ErrorCodes.ExportBlockedSecret);
        Directory.Exists(Path.Combine(root, "diagnostics")).Should().BeFalse();
    }

    private static string ReadEntry(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private sealed class SilentAudit : IAuditLogService
    {
        public void Record(AuditEvent auditEvent)
        {
        }
    }
}
