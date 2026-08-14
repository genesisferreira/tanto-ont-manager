using System.IO.Compression;
using System.Net;
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

public sealed class ExportAuthenticatedDiagnosticUseCase : IExportAuthenticatedDiagnosticUseCase
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IOntAuthSessionStore _sessionStore;
    private readonly LoggingPaths _paths;
    private readonly IAuditLogService _audit;
    private readonly ILogger<ExportAuthenticatedDiagnosticUseCase> _logger;

    public ExportAuthenticatedDiagnosticUseCase(
        IOntAuthSessionStore sessionStore,
        LoggingPaths paths,
        IAuditLogService audit,
        ILogger<ExportAuthenticatedDiagnosticUseCase> logger)
    {
        _sessionStore = sessionStore;
        _paths = paths;
        _audit = audit;
        _logger = logger;
    }

    public Task<Result<AuthenticatedExportResult>> ExecuteAsync(
        ExportAuthenticatedDiagnosticCommand command,
        CancellationToken cancellationToken)
    {
        var snapshot = _sessionStore.Snapshot;
        var session = _sessionStore.DomainSession;
        if (snapshot is null || session is null || !session.IsAuthenticated)
        {
            return Task.FromResult(Result.Failure<AuthenticatedExportResult>(Error.Create(
                ErrorCodes.AuthenticatedExportRequiresSession,
                "Exporte o diagnóstico autenticado somente depois de um login bem-sucedido.")));
        }

        var identity = snapshot.Identity;
        var diagnostics = snapshot.Diagnostics;
        var deviceJson = JsonSerializer.Serialize(new
        {
            Manufacturer = identity.Manufacturer,
            Model = identity.Model,
            HardwareVersion = identity.Firmware.HardwareVersion,
            SoftwareVersion = identity.Firmware.SoftwareVersion,
            BootVersion = identity.Firmware.BootVersion,
            SerialNumber = SensitiveDataMasker.MaskSerial(identity.SerialNumber),
            MacAddress = SensitiveDataMasker.MaskMac(identity.MacAddress)
        }, JsonOptions);

        var ponJson = JsonSerializer.Serialize(new
        {
            diagnostics.Pon.OnuState,
            Temperature = diagnostics.Optical.Temperature,
            TxPower = diagnostics.Optical.TxPower,
            RxPower = diagnostics.Optical.RxPower,
            Voltage = diagnostics.Optical.Voltage,
            BiasCurrent = diagnostics.Optical.BiasCurrent
        }, JsonOptions);

        var wanJson = JsonSerializer.Serialize(diagnostics.WanProfiles.Select(profile => new
        {
            profile.Name,
            Type = profile.Mode ?? profile.LinkType,
            ServiceList = profile.ServiceList,
            LinkType = profile.LinkType,
            IpVersion = profile.AddressFamily,
            IpType = profile.IpType,
            Nat = profile.NatEnabled,
            Vlan = profile.VlanId,
            Priority8021p = profile.Priority8021p,
            Status = profile.ConnectionState,
            IpMasked = profile.Ipv4Address,
            DisconnectReason = profile.DisconnectReason,
            MacMasked = (string?)null
        }), JsonOptions);

        var inventoryJson = JsonSerializer.Serialize(snapshot.Inventory.Select(item => new
        {
            item.Tag,
            TypeAndTag = item.TypeAndTag,
            Origem = item.EvidenceSource,
            Metodo = item.Method,
            ContentType = item.ContentType,
            Tamanho = item.SizeBytes,
            HashSanitizado = item.SanitizedHash,
            Classificacao = item.Classification.ToString(),
            Motivo = item.ClassificationReason,
            FoiAcessada = item.WasAccessed
        }), JsonOptions);

        var summary = BuildSummary(session.Endpoint.Address, snapshot);
        var combined = deviceJson + ponJson + wanJson + inventoryJson + summary;
        combined = AuthenticatedPayloadSanitizer.Sanitize(combined);

        if (AuthenticatedPayloadSanitizer.LooksUnsanitized(combined)
            || ContainsSecret(combined, command.Username, command.Password)
            || ContainsFullIdentifier(combined, identity.SerialNumber, identity.MacAddress)
            || ContainsPppoeSecret(combined))
        {
            _logger.LogWarning("Exportação autenticada cancelada: sanitização não comprovada.");
            return Task.FromResult(Result.Failure<AuthenticatedExportResult>(Error.Create(
                ErrorCodes.SanitizationUnproven,
                "A exportação autenticada foi cancelada porque a sanitização não pôde ser comprovada.")));
        }

        Directory.CreateDirectory(_paths.DiagnosticsDirectory);
        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss");
        var masked = MaskAddress(session.Endpoint.Address.ToString());
        var zipPath = Path.Combine(_paths.DiagnosticsDirectory, $"{stamp}_{masked}_auth.zip");

        var manifest = new
        {
            Product = ProductInfo.Name,
            Version = ProductInfo.Version,
            CreatedAt = DateTimeOffset.Now,
            TargetAddressMasked = masked.Replace('-', '.'),
            IncludesHtml = false,
            IncludesCookies = false,
            IncludesCredentials = false,
            IncludesRawAuthenticatedHtml = false,
            SensitiveIdentifiersMasked = true,
            LoginPostCount = snapshot.LoginPostCount,
            LogoutPostCount = snapshot.LogoutPostCount,
            ConfigPostCount = snapshot.ConfigPostCount,
            PostCount = snapshot.PostCount,
            PagesRead = snapshot.PagesRead,
            HttpMethods = new[] { "GET", "POST" }
        };

        using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            Write(zip, "manifest.json", JsonSerializer.Serialize(manifest, JsonOptions));
            Write(zip, "device-information.json", AuthenticatedPayloadSanitizer.Sanitize(deviceJson));
            Write(zip, "pon-status.json", AuthenticatedPayloadSanitizer.Sanitize(ponJson));
            Write(zip, "wan-summary.json", AuthenticatedPayloadSanitizer.Sanitize(wanJson));
            Write(zip, "safe-read-inventory.json", AuthenticatedPayloadSanitizer.Sanitize(inventoryJson));
            Write(zip, "authenticated-diagnostic-summary.txt", AuthenticatedPayloadSanitizer.Sanitize(summary));
        }

        var inspection = AuthenticatedZipInspector.Inspect(zipPath, identity.SerialNumber, identity.MacAddress);
        if (!inspection.IsAcceptable)
        {
            File.Delete(zipPath);
            return Task.FromResult(Result.Failure<AuthenticatedExportResult>(Error.Create(
                ErrorCodes.AuthenticatedExportInspectionFailed,
                "O ZIP autenticado foi recusado pela inspeção de sanitização e não foi concluído.")));
        }

        _audit.Record(AuditEvent.Create(
            "export-authenticated-diagnostic",
            "exported",
            masked,
            $"zip={Path.GetFileName(zipPath)}; posts={snapshot.PostCount}; pages={snapshot.PagesRead.Count}"));
        _logger.LogInformation("Diagnóstico autenticado sanitizado exportado para {Path}", zipPath);
        return Task.FromResult(Result.Success(new AuthenticatedExportResult(zipPath, inspection)));
    }

    private static void Write(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.SmallestSize);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, Encoding.UTF8);
        writer.Write(content);
    }

    private static bool ContainsSecret(string text, string? username, string? password)
    {
        if (!string.IsNullOrWhiteSpace(username) && username.Length >= 3 && text.Contains(username, StringComparison.Ordinal))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(password) && password.Length >= 3 && text.Contains(password, StringComparison.Ordinal);
    }

    private static bool ContainsFullIdentifier(string text, string? serial, string? mac)
    {
        if (!string.IsNullOrWhiteSpace(serial) && serial.Length >= 6 && text.Contains(serial, StringComparison.Ordinal))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(mac) && mac.Length >= 12 && text.Contains(mac, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsPppoeSecret(string text)
        => RegexContains(text, "(?i)(pppoe\\s*(user(name)?|password)|pppPassword)");

    private static bool RegexContains(string text, string pattern)
        => System.Text.RegularExpressions.Regex.IsMatch(text, pattern);

    private static string MaskAddress(string address)
    {
        var parts = address.Split('.');
        return parts.Length == 4 ? $"{parts[0]}-{parts[1]}-{parts[2]}-x" : "ip-x";
    }

    private static string BuildSummary(IPAddress address, Domain.Sessions.AuthenticatedReadSnapshot snapshot)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Tanto ONT Manager — diagnóstico autenticado sanitizado");
        builder.AppendLine($"Versão: {ProductInfo.Version}");
        builder.AppendLine($"Alvo: {MaskAddress(address.ToString()).Replace('-', '.')}");
        builder.AppendLine($"POST login: {snapshot.LoginPostCount}");
        builder.AppendLine($"POST logout: {snapshot.LogoutPostCount}");
        builder.AppendLine($"POST configuração: {snapshot.ConfigPostCount}");
        builder.AppendLine($"Páginas GET: {string.Join(", ", snapshot.PagesRead)}");
        builder.AppendLine($"Hash sanitizado: {snapshot.LastSanitizedHash}");
        builder.AppendLine("HTML bruto autenticado: não incluído");
        builder.AppendLine("Cookies: não incluídos");
        builder.AppendLine($"IncludesCookies: false");
        builder.AppendLine($"IncludesCredentials: false");
        builder.AppendLine($"IncludesRawAuthenticatedHtml: false");
        builder.AppendLine($"SensitiveIdentifiersMasked: true");
        return builder.ToString();
    }
}
