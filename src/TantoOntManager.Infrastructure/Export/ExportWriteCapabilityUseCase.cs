using System.Text.Json;
using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Observation;
using TantoOntManager.Infrastructure.DependencyInjection;

namespace TantoOntManager.Infrastructure.Export;

public sealed class ExportWriteCapabilityUseCase : IExportWriteCapabilityUseCase
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IObservationSessionStore _observation;
    private readonly LoggingPaths _paths;
    private readonly ILogger<ExportWriteCapabilityUseCase> _logger;

    public ExportWriteCapabilityUseCase(
        IObservationSessionStore observation,
        LoggingPaths paths,
        ILogger<ExportWriteCapabilityUseCase> logger)
    {
        _observation = observation;
        _paths = paths;
        _logger = logger;
    }

    public Task<Result<WriteCapabilityExportResult>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var snapshot = _observation.Engine?.Snapshot() ?? _observation.LastSnapshot;
        var report = snapshot?.WriteCapability ?? _observation.Engine?.WriteCapability;
        if (snapshot is null || report is null)
        {
            return Task.FromResult(Result.Failure<WriteCapabilityExportResult>(Error.Create(
                ErrorCodes.ObservationExportRequiresCapture,
                "Exporte o diagnóstico de capacidade depois de observar a sessão autenticada.")));
        }

        var json = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(new
        {
            Product = ProductInfo.Name,
            Version = ProductInfo.Version,
            report.Manufacturer,
            report.Model,
            report.SoftwareVersion,
            Firmware = report.Firmware.ToString(),
            report.ObservedUsername,
            report.MenuLeaves,
            report.WanProfiles,
            report.TypeOptions,
            report.LinkTypeOptions,
            report.IpTypeOptions,
            report.BlockedOrHiddenControls,
            Evidences = report.Evidences.Select(item => new { item.Code, item.Description, item.Source }),
            PppoeAvailable = WriteCapabilityReport.AvailabilityLabel(report.PppoeAvailable),
            CreateProfileAvailable = WriteCapabilityReport.AvailabilityLabel(report.CreateProfileAvailable),
            ApplySaveAvailable = WriteCapabilityReport.AvailabilityLabel(report.ApplySaveAvailable),
            Conclusion = report.Conclusion.ToString(),
            report.OperatorMessage,
            report.NextStep,
            report.PageScrolledToFooter,
            report.WanPageObserved,
            report.WriteCandidatesIntercepted,
            ConfigurationRequestsSent = 0,
            StructureSha256 = ObservationSanitizer.Sha256(string.Join('|', report.IpTypeOptions.Concat(report.TypeOptions).Concat(report.MenuLeaves)))
        }, JsonOptions));
        var summary = WriteCapabilityClassifier.ToOperatorText(report);
        var manifest = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(new
        {
            Product = ProductInfo.Name,
            Version = ProductInfo.Version,
            IncludesCookies = false,
            IncludesCredentials = false,
            IncludesTokens = false,
            IncludesRawRequestBody = false,
            IncludesRawAuthenticatedHtml = false,
            IncludesAuthorizationHeaders = false,
            IncludesFullHeaders = false,
            SensitiveIdentifiersMasked = true,
            ConfigurationRequestsSent = 0,
            RequestBlockedBeforeNetwork = true
        }, JsonOptions));

        var combined = json + summary + manifest;
        var inspection = WriteContractContentInspector.Inspect(
            combined,
            ["write-capability-report.json", "write-capability-summary.txt", "manifest.json"]);
        if (!inspection.IsAcceptable || ObservationSanitizer.LooksUnsanitized(combined))
        {
            return Task.FromResult(Result.Failure<WriteCapabilityExportResult>(Error.Create(
                ErrorCodes.WriteCapabilityExportInspectionFailed,
                "A exportação do diagnóstico de capacidade foi recusada porque a sanitização não pôde ser comprovada.")));
        }

        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss");
        var directory = Path.Combine(_paths.WriteCapabilityReportsDirectory, stamp);
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "write-capability-report.json"), json);
            File.WriteAllText(Path.Combine(directory, "write-capability-summary.txt"), summary);
            File.WriteAllText(Path.Combine(directory, "manifest.json"), manifest);
            _logger.LogInformation("Diagnóstico de capacidade de escrita exportado para {Path}", directory);
            return Task.FromResult(Result.Success(new WriteCapabilityExportResult(directory, inspection)));
        }
        catch (Exception)
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, true);
                }
            }
            catch (IOException)
            {
                // melhor esforço
            }

            throw;
        }
    }
}
