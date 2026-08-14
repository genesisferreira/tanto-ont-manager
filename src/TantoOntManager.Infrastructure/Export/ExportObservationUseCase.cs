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

public sealed class ExportObservationUseCase : IExportObservationUseCase
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IObservationSessionStore _observation;
    private readonly IOntAuthSessionStore _auth;
    private readonly LoggingPaths _paths;
    private readonly ILogger<ExportObservationUseCase> _logger;

    public ExportObservationUseCase(
        IObservationSessionStore observation,
        IOntAuthSessionStore auth,
        LoggingPaths paths,
        ILogger<ExportObservationUseCase> logger)
    {
        _observation = observation;
        _auth = auth;
        _paths = paths;
        _logger = logger;
    }

    public Task<Result<ObservationExportResult>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var snapshot = _observation.Engine?.Snapshot() ?? _observation.LastSnapshot;
        if (snapshot is null || snapshot.Gets.Count + snapshot.Blocked.Count == 0)
        {
            return Task.FromResult(Result.Failure<ObservationExportResult>(Error.Create(
                ErrorCodes.ObservationExportRequiresCapture,
                "Exporte a observação sanitizada somente depois de uma captura GET.")));
        }

        var contracts = snapshot.Gets
            .Where(item => item.Classification == ObservedGetClassification.DataEndpoint)
            .Select(item => new
            {
                item.Sequence,
                Tela = item.Screen.ToOperatorLabel(),
                GET = item.Path,
                Type = item.Type,
                Tag = item.Tag,
                Extras = item.ExtraParameterNames,
                Valores = item.ExtraValuesSanitized,
                HTTP = item.StatusCode,
                item.ContentType,
                Tamanho = item.SizeBytes,
                Hash = item.Sha256,
                NovoOuAlterado = item.IsNewOrChanged,
                Classificacao = item.Classification.ToString(),
                Referer = item.RequestContext?.HasReferer ?? false,
                Origin = item.RequestContext?.HasOrigin ?? false,
                XRequestedWith = item.RequestContext?.HasXRequestedWith ?? false,
                Accept = item.RequestContext?.HasAccept ?? false,
                AcceptLanguage = item.RequestContext?.HasAcceptLanguage ?? false,
                CookieNames = item.RequestContext?.CookieNames ?? [],
                SessionTokenPresent = item.RequestContext?.SessionTokenPresent ?? false,
                SessionTokenLength = item.RequestContext?.SessionTokenLength ?? 0,
                InitiatorKind = item.RequestContext?.InitiatorKind
            });
        var structures = snapshot.Structures.Select(item => new
        {
            Url = item.NormalizedUrl,
            item.Format,
            Chaves = item.Keys,
            Campos = item.FieldIds,
            Colunas = item.ColumnNames,
            Registros = item.RecordCount,
            Tipos = item.ApproximateTypes,
            AmostrasMascaradas = item.MaskedSampleValues
        });
        var blocked = snapshot.Blocked.Select(item => new
        {
            item.Sequence,
            Metodo = item.Method,
            Path = item.PathSanitized,
            item.Reason,
            Host = ObservationSanitizer.SanitizeText(item.Host)
        });
        var summary = ObservationSanitizer.SanitizeText(snapshot.SummaryText);
        var jsonContracts = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(contracts, JsonOptions));
        var jsonStructures = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(structures, JsonOptions));
        var jsonBlocked = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(blocked, JsonOptions));
        var manifest = ObservationSanitizer.SanitizeText(JsonSerializer.Serialize(new
        {
            Product = ProductInfo.Name,
            Version = ProductInfo.Version,
            IncludesCookies = false,
            IncludesCredentials = false,
            IncludesTokens = false,
            IncludesRawAuthenticatedBody = false,
            SensitiveIdentifiersMasked = true,
            ConfigurationRequestsSent = 0,
            LoginPostCount = _auth.Transport?.LoginPostCount ?? 0,
            ObserverPostsBlocked = snapshot.Counters.PostsObservedAndBlocked,
            GetsObserved = snapshot.Counters.GetsObserved,
            GetsAllowed = snapshot.Counters.GetsAllowed
        }, JsonOptions));

        var combined = summary + jsonContracts + jsonStructures + jsonBlocked + manifest;
        if (ObservationSanitizer.LooksUnsanitized(combined)
            || combined.Contains("<html", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("Set-Cookie", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(Result.Failure<ObservationExportResult>(Error.Create(
                ErrorCodes.SanitizationUnproven,
                "A exportação da observação foi cancelada porque a sanitização não pôde ser comprovada.")));
        }

        Directory.CreateDirectory(_paths.DiagnosticsDirectory);
        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss");
        var zipPath = Path.Combine(_paths.DiagnosticsDirectory, $"{stamp}_192-168-100-x_observation.zip");
        using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            Write(zip, "observation-summary.txt", summary);
            Write(zip, "observed-get-contracts.json", jsonContracts);
            Write(zip, "response-structures.json", jsonStructures);
            Write(zip, "blocked-requests.json", jsonBlocked);
            Write(zip, "manifest.json", manifest);
        }

        var inspection = ObservationZipInspector.Inspect(zipPath);
        if (!inspection.IsAcceptable)
        {
            File.Delete(zipPath);
            return Task.FromResult(Result.Failure<ObservationExportResult>(Error.Create(
                ErrorCodes.AuthenticatedExportInspectionFailed,
                "O ZIP de observação foi recusado pela inspeção de sanitização.")));
        }

        _logger.LogInformation("Observação sanitizada exportada para {Path}", zipPath);
        return Task.FromResult(Result.Success(new ObservationExportResult(zipPath, inspection)));
    }

    private static void Write(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.SmallestSize);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, Encoding.UTF8);
        writer.Write(content);
    }
}
