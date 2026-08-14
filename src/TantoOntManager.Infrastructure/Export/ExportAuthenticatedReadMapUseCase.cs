using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Export;
using TantoOntManager.Infrastructure.DependencyInjection;
using TantoOntManager.Security.Export;

namespace TantoOntManager.Infrastructure.Export;

public sealed class ExportAuthenticatedReadMapUseCase : IExportAuthenticatedReadMapUseCase
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IOntAuthSessionStore _sessionStore;
    private readonly LoggingPaths _paths;
    private readonly IAuditLogService _audit;
    private readonly ILogger<ExportAuthenticatedReadMapUseCase> _logger;

    public ExportAuthenticatedReadMapUseCase(
        IOntAuthSessionStore sessionStore,
        LoggingPaths paths,
        IAuditLogService audit,
        ILogger<ExportAuthenticatedReadMapUseCase> logger)
    {
        _sessionStore = sessionStore;
        _paths = paths;
        _audit = audit;
        _logger = logger;
    }

    public Task<Result<AuthenticatedExportResult>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var map = _sessionStore.ReadMap;
        var session = _sessionStore.DomainSession;
        if (map is null || session is null || !session.IsAuthenticated)
        {
            return Task.FromResult(Result.Failure<AuthenticatedExportResult>(Error.Create(
                ErrorCodes.AuthenticatedMapRequiresSession,
                "Exporte o mapa sanitizado somente depois de Mapear leituras em uma sessão autenticada.")));
        }

        var json = JsonSerializer.Serialize(new
        {
            Produto = ProductInfo.Name,
            Versao = ProductInfo.Version,
            Candidatos = map.TotalCandidates,
            SafeRead = map.SafeReadCount,
            Bloqueados = map.BlockedCount,
            Duplicados = map.DuplicateCount,
            LoginPostCount = map.LoginPostCount,
            LogoutPostCount = map.LogoutPostCount,
            ConfigPostCount = map.ConfigPostCount,
            PrioritariasEncontradas = map.PriorityFound,
            PrioritariasAusentes = map.PriorityMissing,
            PadroesSemTagLiteral = map.UnresolvedPatterns,
            Nota = map.Note,
            Entradas = map.Entries.Select(item => new
            {
                TextoMenu = item.MenuText,
                Type = item.Type,
                Tag = item.Tag,
                Origem = item.EvidenceSource,
                Classificacao = item.Classification.ToString(),
                Motivo = item.Reason,
                Http = item.HttpStatus,
                ContentType = item.ContentType,
                Tamanho = item.SizeBytes,
                Hash = item.SanitizedHash
            })
        }, JsonOptions);

        var text = map.ToOperatorText();
        json = AuthenticatedPayloadSanitizer.Sanitize(json);
        text = AuthenticatedPayloadSanitizer.Sanitize(text);
        var combined = json + text;
        if (AuthenticatedPayloadSanitizer.LooksUnsanitized(combined)
            || combined.Contains("<html", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("Set-Cookie", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("_sessionTOKEN=", StringComparison.Ordinal)
            || combined.Contains("SID_HTTPS_=", StringComparison.Ordinal))
        {
            return Task.FromResult(Result.Failure<AuthenticatedExportResult>(Error.Create(
                ErrorCodes.SanitizationUnproven,
                "A exportação do mapa foi cancelada porque a sanitização não pôde ser comprovada.")));
        }

        Directory.CreateDirectory(_paths.DiagnosticsDirectory);
        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss");
        var masked = MaskAddress(session.Endpoint.Address.ToString());
        var zipPath = Path.Combine(_paths.DiagnosticsDirectory, $"{stamp}_{masked}_read-map.zip");
        using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            Write(zip, "authenticated-read-map.json", json);
            Write(zip, "authenticated-read-map.txt", text);
        }

        var inspection = new AuthenticatedZipInspection(
            false,
            false,
            false,
            true,
            ["authenticated-read-map.json", "authenticated-read-map.txt"]);
        _audit.Record(AuditEvent.Create(
            "export-authenticated-read-map",
            "exported",
            masked,
            $"zip={Path.GetFileName(zipPath)}; candidatos={map.TotalCandidates}"));
        _logger.LogInformation("Mapa autenticado sanitizado exportado para {Path}", zipPath);
        return Task.FromResult(Result.Success(new AuthenticatedExportResult(zipPath, inspection)));
    }

    private static void Write(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.SmallestSize);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, Encoding.UTF8);
        writer.Write(content);
    }

    private static string MaskAddress(string address)
    {
        var parts = address.Split('.');
        return parts.Length == 4 ? $"{parts[0]}-{parts[1]}-{parts[2]}-x" : "ip-x";
    }
}
