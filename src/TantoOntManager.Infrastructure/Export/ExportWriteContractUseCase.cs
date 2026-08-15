using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Observation;
using TantoOntManager.Infrastructure.DependencyInjection;

namespace TantoOntManager.Infrastructure.Export;

public sealed class ExportWriteContractUseCase : IExportWriteContractUseCase
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IObservationSessionStore _observation;
    private readonly IOntAuthSessionStore _auth;
    private readonly LoggingPaths _paths;
    private readonly ILogger<ExportWriteContractUseCase> _logger;

    public ExportWriteContractUseCase(
        IObservationSessionStore observation,
        IOntAuthSessionStore auth,
        LoggingPaths paths,
        ILogger<ExportWriteContractUseCase> logger)
    {
        _observation = observation;
        _auth = auth;
        _paths = paths;
        _logger = logger;
    }

    public Task<Result<WriteContractExportResult>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var snapshot = _observation.Engine?.Snapshot() ?? _observation.LastSnapshot;
        var candidate = snapshot?.WriteCandidate;
        if (snapshot is null || candidate is null)
        {
            return Task.FromResult(Result.Failure<WriteContractExportResult>(Error.Create(
                ErrorCodes.WriteCaptureNotCaptured,
                "Exporte a proposta somente depois de interceptar um candidato bloqueado.")));
        }

        if (candidate.ConfigurationRequestsSent != 0 || candidate.NetworkRequestSent || !candidate.BlockedBeforeNetwork)
        {
            return Task.FromResult(Result.Failure<WriteContractExportResult>(Error.Create(
                ErrorCodes.WriteCaptureExportInspectionFailed,
                "A proposta foi recusada porque a requisição não permanece bloqueada antes da rede.")));
        }

        var proposal = WriteContractProposalBuilder.FromCandidate(candidate);
        var proposalJson = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(new
        {
            Product = ProductInfo.Name,
            Version = ProductInfo.Version,
            proposal.Status,
            proposal.NetworkRequestSent,
            proposal.HumanReviewRequired,
            proposal.BackupContractRequired,
            proposal.RollbackContractRequired,
            proposal.Phase2BRequired,
            proposal.AdapterModified,
            proposal.AllowlistModified,
            Candidate = SanitizeCandidate(candidate)
        }, JsonOptions));
        var summary = WriteContractProposalBuilder.ToSummaryText(candidate);
        var blocked = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(new
        {
            candidate.Sequence,
            Metodo = candidate.Method,
            Path = candidate.PathSanitized,
            candidate.ContentType,
            Query = candidate.QueryParameterNames,
            Campos = candidate.Fields.Select(field => new
            {
                field.Name,
                field.Sensitive,
                field.Present,
                field.LengthBucket,
                field.StructuralType,
                field.Value
            }),
            candidate.ActionName,
            Referer = candidate.RefererPathSanitized,
            candidate.Initiator,
            Prerequisites = candidate.PrerequisiteGets,
            candidate.StructureSha256,
            candidate.BlockedBeforeNetwork,
            candidate.BlockReason,
            candidate.NetworkRequestSent,
            candidate.ConfigurationRequestsSent
        }, JsonOptions));
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
            RequestBlockedBeforeNetwork = true,
            LoginPostCount = _auth.Transport?.LoginPostCount ?? 0,
            ObserverPostsBlocked = snapshot.Counters.PostsObservedAndBlocked
        }, JsonOptions));

        var combined = proposalJson + summary + blocked + manifest;
        var inspection = WriteContractContentInspector.Inspect(
            combined,
            WriteContractContentInspector.AllowedEntryNames);
        if (!inspection.IsAcceptable || ObservationSanitizer.LooksUnsanitized(combined))
        {
            return Task.FromResult(Result.Failure<WriteContractExportResult>(Error.Create(
                ErrorCodes.WriteCaptureExportInspectionFailed,
                "A exportação da proposta foi recusada porque a sanitização não pôde ser comprovada.")));
        }

        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss");
        var directory = Path.Combine(_paths.WriteContractProposalsDirectory, stamp);
        var zipPath = Path.Combine(_paths.WriteContractProposalsDirectory, stamp + "_write-contract.zip");
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "write-contract-proposal.json"), proposalJson);
            File.WriteAllText(Path.Combine(directory, "write-contract-summary.txt"), summary);
            File.WriteAllText(Path.Combine(directory, "blocked-request.json"), blocked);
            File.WriteAllText(Path.Combine(directory, "manifest.json"), manifest);

            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                Write(zip, "write-contract-proposal.json", proposalJson);
                Write(zip, "write-contract-summary.txt", summary);
                Write(zip, "blocked-request.json", blocked);
                Write(zip, "manifest.json", manifest);
            }

            var committed = WriteContractExportFinalizer.InspectAndKeepOrDelete(directory, zipPath);
            if (committed.IsFailure)
            {
                return Task.FromResult(committed);
            }

            _logger.LogInformation("Proposta de gravação sanitizada exportada para {Path}", directory);
            return Task.FromResult(committed);
        }
        catch (Exception)
        {
            WriteContractExportFinalizer.DeleteIncomplete(directory, zipPath);
            throw;
        }
    }

    private static object SanitizeCandidate(WriteContractCandidate candidate)
        => new
        {
            candidate.Sequence,
            candidate.Screen,
            candidate.Method,
            candidate.PathSanitized,
            candidate.QueryParameterNames,
            candidate.ContentType,
            Fields = candidate.Fields.Select(field => new
            {
                field.Name,
                field.Sensitive,
                field.Present,
                field.LengthBucket,
                field.StructuralType,
                field.Value
            }),
            candidate.ActionName,
            candidate.RefererPathSanitized,
            candidate.Initiator,
            candidate.PrerequisiteGets,
            candidate.StructureSha256,
            candidate.BlockedBeforeNetwork,
            candidate.BlockReason,
            candidate.NetworkRequestSent,
            candidate.ConfigurationRequestsSent,
            candidate.FieldCount,
            candidate.SensitiveFieldCount
        };

    private static void Write(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.SmallestSize);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, Encoding.UTF8);
        writer.Write(content);
    }
}
