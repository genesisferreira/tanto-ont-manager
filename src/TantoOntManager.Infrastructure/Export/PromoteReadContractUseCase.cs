using System.Text.Json;
using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Observation;
using TantoOntManager.Infrastructure.DependencyInjection;

namespace TantoOntManager.Infrastructure.Export;

public sealed class PromoteReadContractUseCase : IPromoteReadContractUseCase
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IObservationSessionStore _observation;
    private readonly IOntAuthSessionStore _auth;
    private readonly LoggingPaths _paths;
    private readonly ILogger<PromoteReadContractUseCase> _logger;

    public PromoteReadContractUseCase(
        IObservationSessionStore observation,
        IOntAuthSessionStore auth,
        LoggingPaths paths,
        ILogger<PromoteReadContractUseCase> logger)
    {
        _observation = observation;
        _auth = auth;
        _paths = paths;
        _logger = logger;
    }

    public Task<Result<string>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var snapshot = _observation.Engine?.Snapshot() ?? _observation.LastSnapshot;
        if (snapshot is null)
        {
            return Task.FromResult(Result.Failure<string>(Error.Create(
                ErrorCodes.ObservationExportRequiresCapture,
                "Promova o contrato somente depois de observar GETs.")));
        }

        var firmware = _auth.Snapshot?.FirmwareCompatibility ?? FirmwareCompatibility.Unconfirmed;
        var version = _auth.Snapshot?.Identity.Firmware.SoftwareVersion;
        var proposals = ReadContractProposalBuilder.FromObservation(snapshot.Gets, snapshot.Structures, firmware, version);
        var payload = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(new
        {
            Product = ProductInfo.Name,
            Version = ProductInfo.Version,
            FirmwareStatus = firmware.ToString(),
            FirmwareTarget = version ?? "Unconfirmed",
            WriteForbidden = true,
            AdapterModified = false,
            AllowlistModified = false,
            Note = firmware == FirmwareCompatibility.Unconfirmed
                ? "Firmware Unconfirmed; escrita proibida. Esta proposta não altera o adaptador F6201B."
                : "Proposta local. O adaptador homologado permanece inalterado até revisão humana.",
            Propostas = proposals
        }, JsonOptions));

        var directory = Path.Combine(_paths.DiagnosticsDirectory, "proposals");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss") + "_read-contract-proposal.json");
        File.WriteAllText(path, payload);
        _logger.LogInformation("Proposta de contrato de leitura gravada em {Path} sem alterar o adaptador", path);
        return Task.FromResult(Result.Success(path));
    }
}
