using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Detection;
using TantoOntManager.Infrastructure.DependencyInjection;
using TantoOntManager.Security.Export;

namespace TantoOntManager.Infrastructure.Export;

public sealed class ExportPublicDiagnosticUseCase : IExportPublicDiagnosticUseCase
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly IPublicProbeCache _cache;
    private readonly LoggingPaths _paths;
    private readonly IAuditLogService _audit;
    private readonly ILogger<ExportPublicDiagnosticUseCase> _logger;

    public ExportPublicDiagnosticUseCase(
        IPublicProbeCache cache,
        LoggingPaths paths,
        IAuditLogService audit,
        ILogger<ExportPublicDiagnosticUseCase> logger)
    {
        _cache = cache;
        _paths = paths;
        _audit = audit;
        _logger = logger;
    }

    public Task<Result<string>> ExecuteAsync(ExportPublicDiagnosticCommand command, CancellationToken cancellationToken)
    {
        var document = _cache.LastDocument;
        var observation = _cache.LastObservation ?? document?.Observation;
        if (document is null || string.IsNullOrWhiteSpace(document.Body))
        {
            return Task.FromResult(Result.Failure<string>(Error.Create(
                ErrorCodes.PublicPageUnreadable,
                "Não há resposta pública capturada para exportar. Execute Detectar ONT primeiro.")));
        }

        var scan = PublicExportSecretScanner.Scan(
            document.Body,
            observation?.SafeHeaders ?? [],
            command.Username,
            command.Password);
        if (scan.Blocked)
        {
            _logger.LogWarning("Exportação pública bloqueada: {Reasons}", string.Join("; ", scan.Reasons));
            return Task.FromResult(Result.Failure<string>(Error.Create(
                ErrorCodes.ExportBlockedSecret,
                "A exportação foi cancelada porque o pacote conteria dado sensível.",
                string.Join(" ", scan.Reasons))));
        }

        Directory.CreateDirectory(_paths.DiagnosticsDirectory);
        var hash = observation?.BodySha256
                   ?? Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(document.Body))).ToLowerInvariant();
        var shortHash = hash[..Math.Min(8, hash.Length)];
        var masked = MaskAddress(document.Endpoint.Address.ToString());
        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss");
        var zipPath = Path.Combine(_paths.DiagnosticsDirectory, $"{stamp}_{masked}_{shortHash}.zip");

        var manifest = new PublicExportManifest(
            "Tanto ONT Manager",
            ProductInfo.Version,
            DateTimeOffset.Now,
            masked.Replace('-', '.'),
            document.Endpoint.Scheme,
            document.Endpoint.Port,
            document.StatusCode,
            observation?.FinalUri,
            observation?.RedirectCount ?? 0,
            document.Title,
            observation?.BodyLengthBytes ?? Encoding.UTF8.GetByteCount(document.Body),
            hash,
            document.Methods,
            false,
            false);

        using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            WriteEntry(zip, "manifest.json", JsonSerializer.Serialize(manifest, JsonOptions));
            WriteEntry(zip, "public-response.html", document.Body);
            WriteEntry(zip, "public-response.sha256", hash + Environment.NewLine);
            WriteEntry(zip, "certificate.json", JsonSerializer.Serialize(observation?.Certificate, JsonOptions));
            WriteEntry(zip, "diagnostic-summary.txt", BuildSummary(manifest, observation, document.Methods));
        }

        _audit.Record(AuditEvent.Create(
            "export-public-diagnostic",
            "exported",
            masked,
            $"zip={Path.GetFileName(zipPath)}; methods={string.Join(',', document.Methods.Distinct())}"));
        _logger.LogInformation("Diagnóstico público exportado para {Path}", zipPath);

        return Task.FromResult(Result.Success(zipPath));
    }

    private static void WriteEntry(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.SmallestSize);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, Encoding.UTF8);
        writer.Write(content);
    }

    private static string MaskAddress(string address)
    {
        var parts = address.Split('.');
        if (parts.Length != 4)
        {
            return "ip-x";
        }

        return $"{parts[0]}-{parts[1]}-{parts[2]}-x";
    }

    private static string BuildSummary(
        PublicExportManifest manifest,
        Domain.Network.HttpPublicObservation? observation,
        IReadOnlyList<string> methods)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Tanto ONT Manager — diagnóstico público sanitizado");
        builder.AppendLine($"Versão: {manifest.Version}");
        builder.AppendLine($"Criado em: {manifest.CreatedAt:O}");
        builder.AppendLine($"Alvo: {manifest.TargetAddressMasked}");
        builder.AppendLine($"Protocolo: {manifest.Scheme} porta {manifest.Port}");
        builder.AppendLine($"Status: {manifest.StatusCode}");
        builder.AppendLine($"URI final: {manifest.FinalUri}");
        builder.AppendLine($"Redirects: {manifest.RedirectCount}");
        builder.AppendLine($"Título: {manifest.Title}");
        builder.AppendLine($"Bytes: {manifest.BodyLengthBytes}");
        builder.AppendLine($"SHA-256: {manifest.BodySha256}");
        builder.AppendLine($"Métodos: {string.Join(", ", methods.Distinct())}");
        builder.AppendLine($"Cookies incluídos: {manifest.IncludesCookies}");
        builder.AppendLine($"Credenciais incluídas: {manifest.IncludesCredentials}");
        if (observation is not null)
        {
            builder.AppendLine($"Content-Type: {observation.ContentType}");
            builder.AppendLine($"Charset: {observation.Charset}");
            builder.AppendLine($"Encoding: {observation.DetectedEncoding}");
            builder.AppendLine($"Comprimido: {observation.ContentWasCompressed}");
            builder.AppendLine($"Timeout: {observation.TimedOut}");
            builder.AppendLine($"Conexão: {observation.ConnectDuration.TotalMilliseconds:0} ms");
            builder.AppendLine($"Total: {observation.TotalDuration.TotalMilliseconds:0} ms");
            builder.AppendLine($"TLS: {observation.Certificate.ErrorCategory}");
            builder.AppendLine($"Certificado: {observation.Certificate.Subject}");
            builder.AppendLine($"Emissor: {observation.Certificate.Issuer}");
            builder.AppendLine($"Impressão SHA-256: {observation.Certificate.Sha256Fingerprint}");
            builder.AppendLine($"Exceção local: {observation.Certificate.AcceptedByLocalException}");
        }

        builder.AppendLine();
        builder.AppendLine("Somente GET público. Nenhuma autenticação ou escrita foi realizada.");
        return builder.ToString();
    }
}
