using System.IO.Compression;
using System.Net;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Application.UseCases;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Infrastructure.DependencyInjection;

namespace TantoOntManager.Application.Tests;

public sealed class LabRealOntHomologationTests
{
    [Fact]
    public async Task Detects_and_exports_public_f6201b_when_lab_flag_is_set()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("TANTO_LAB_ONT"), "1", StringComparison.Ordinal))
        {
            return;
        }

        var root = Path.Combine(Path.GetTempPath(), "tanto-lab-" + Guid.NewGuid().ToString("N"));
        var services = new ServiceCollection();
        services.AddTantoOntManager(root);
        await using var provider = services.BuildServiceProvider();
        var detect = provider.GetRequiredService<IDetectOntUseCase>();
        var export = provider.GetRequiredService<IExportPublicDiagnosticUseCase>();
        var cache = provider.GetRequiredService<IPublicProbeCache>();

        var report = await detect.ExecuteAsync(
            new DetectOntCommand(null, IPAddress.Parse("192.168.100.1"), true),
            CancellationToken.None);

        var exported = await export.ExecuteAsync(new ExportPublicDiagnosticCommand(null, null), CancellationToken.None);
        var dump = $"status={report.Status} title={report.PublicObservation?.Title} http={report.PublicObservation?.StatusDisplay} bytes={report.PublicObservation?.BodyLengthBytes} hash={report.PublicObservation?.ShortHash} frames={report.PublicObservation?.FrameUris.Count} methods={string.Join(',', report.PublicObservation?.HttpMethodsUsed ?? Array.Empty<string>())} rec={string.Join('|', report.Recommendations.Select(item => item.Title))} export={exported.Error?.Message ?? exported.Value}";

        report.PublicObservation.Should().NotBeNull(dump);
        report.PublicObservation!.HttpMethodsUsed.Should().OnlyContain(method => method == "GET" || method == "HEAD");
        report.PublicObservation.HttpMethodsUsed.Should().NotContain("POST");
        exported.IsSuccess.Should().BeTrue(dump);

        using var zip = ZipFile.OpenRead(exported.Value!);
        zip.Entries.Select(entry => entry.Name).Should().BeEquivalentTo(
            "manifest.json",
            "public-response.html",
            "public-response.sha256",
            "certificate.json",
            "diagnostic-summary.txt");
        var html = Read(zip, "public-response.html");
        html.Should().NotContain("Set-Cookie");
        var diagnosticsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "TantoTelecom",
            "TantoOntManager",
            "diagnostics");
        Directory.CreateDirectory(diagnosticsDir);
        File.Copy(exported.Value!, Path.Combine(diagnosticsDir, Path.GetFileName(exported.Value!)), overwrite: true);

        report.Device.Should().NotBeNull(dump + " htmlPrefix=" + html[..Math.Min(400, html.Length)]);
        report.Device!.Identity.Manufacturer.Should().Be(ManufacturerNames.Zte);
        report.Device.Identity.Model.Should().Be(DeviceModelIds.ZteF6201B);
        report.Status.Should().Be(ApplicationStatus.Detected);
        cache.LastDocument!.Methods.Should().OnlyContain(method => method == "GET");
    }

    private static string Read(ZipArchive zip, string name)
    {
        var entry = zip.GetEntry(name) ?? throw new InvalidOperationException(name);
        using var stream = entry.Open();
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
