using System.Text.Json;
using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Observation;
using TantoOntManager.Infrastructure.DependencyInjection;

namespace TantoOntManager.Infrastructure.Export;

public sealed class PromoteWriteContractUseCase : IPromoteWriteContractUseCase
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IObservationSessionStore _observation;
    private readonly LoggingPaths _paths;
    private readonly ILogger<PromoteWriteContractUseCase> _logger;

    public PromoteWriteContractUseCase(
        IObservationSessionStore observation,
        LoggingPaths paths,
        ILogger<PromoteWriteContractUseCase> logger)
    {
        _observation = observation;
        _paths = paths;
        _logger = logger;
    }

    public Task<Result<string>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var snapshot = _observation.Engine?.Snapshot() ?? _observation.LastSnapshot;
        var gate = WriteContractPromotionGate.Evaluate(snapshot);
        if (gate.IsFailure)
        {
            return Task.FromResult(Result.Failure<string>(gate.Error!));
        }

        var candidate = snapshot!.WriteCandidate!;

        var proposal = WriteContractProposalBuilder.FromCandidate(candidate);
        var payload = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(new
        {
            Product = ProductInfo.Name,
            Version = ProductInfo.Version,
            proposal.Status,
            proposal.NetworkRequestSent,
            proposal.HumanReviewRequired,
            proposal.BackupContractRequired,
            proposal.RollbackContractRequired,
            proposal.Phase2BRequired,
            AdapterModified = false,
            AllowlistModified = false,
            WriteAllowlistEmpty = F6201BV9310P8N1WriteAllowlist.IsEmpty,
            Note = "Proposta local CandidateOnly. O adaptador de leitura F6201B permanece inalterado. A allowlist de escrita continua vazia. Fase 2B exige revisão humana, backup e rollback.",
            Candidate = new
            {
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
                candidate.StructureSha256,
                candidate.BlockedBeforeNetwork,
                candidate.NetworkRequestSent,
                candidate.ConfigurationRequestsSent
            }
        }, JsonOptions));

        if (WriteContractContentInspector.LooksUnsafe(payload) || ObservationSanitizer.LooksUnsanitized(payload))
        {
            return Task.FromResult(Result.Failure<string>(Error.Create(
                ErrorCodes.WriteCaptureExportInspectionFailed,
                "A promoção local foi recusada porque a sanitização não pôde ser comprovada.")));
        }

        Directory.CreateDirectory(_paths.WriteContractProposalsDirectory);
        var path = Path.Combine(
            _paths.WriteContractProposalsDirectory,
            DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss") + "_write-contract-proposal.json");
        File.WriteAllText(path, payload);
        _logger.LogInformation(
            "Proposta local de gravação gravada em {Path} sem alterar o adaptador nem a allowlist",
            path);
        return Task.FromResult(Result.Success(path));
    }
}
