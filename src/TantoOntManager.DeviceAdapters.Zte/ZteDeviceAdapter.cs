using Microsoft.Extensions.Logging;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.DeviceAdapters.Zte.Parsing;

namespace TantoOntManager.DeviceAdapters.Zte;

public sealed class ZteDeviceAdapter : IOntDeviceAdapter
{
    public const string Id = "zte-zxhn-public-v1";

    private readonly IPublicWebReader _publicWebReader;
    private readonly ILogger<ZteDeviceAdapter> _logger;

    public ZteDeviceAdapter(IPublicWebReader publicWebReader, ILogger<ZteDeviceAdapter> logger)
    {
        _publicWebReader = publicWebReader;
        _logger = logger;
    }

    public string AdapterId => Id;

    public string Manufacturer => ManufacturerNames.Zte;

    public IReadOnlyCollection<string> SupportedModels { get; } =
    [
        DeviceModelIds.ZteF6201B,
        DeviceModelIds.ZteF6600P,
        DeviceModelIds.ZteF670L
    ];

    public async Task<AdapterProbeResult> ProbeAsync(OntEndpoint endpoint, CancellationToken cancellationToken)
    {
        var document = await _publicWebReader.GetRootAsync(endpoint, cancellationToken);
        if (document is null)
        {
            return AdapterProbeResult.NoMatch(
                AdapterId,
                endpoint,
                Error.Create(ErrorCodes.PublicPageUnreadable, "A página pública não pôde ser lida."));
        }

        var analysis = ZtePublicPageAnalyzer.Analyze(document.Title, document.ServerHeader, document.Body);
        if (analysis.HasConflict)
        {
            _logger.LogInformation("Probe ZTE com evidências conflitantes em {Endpoint}", endpoint);
            return AdapterProbeResult.NoMatch(
                AdapterId,
                endpoint,
                Error.Create(ErrorCodes.ConflictingEvidence, "Evidências públicas conflitantes; o modelo não foi identificado."));
        }

        var manufacturerOnly = analysis.LooksLikeZte && analysis.Model is null && analysis.Confidence >= 0.35;
        var identifiedModel = analysis.Model is not null && analysis.LooksLikeZte && analysis.Confidence >= 0.55;
        if (!identifiedModel && !manufacturerOnly)
        {
            _logger.LogInformation(
                "Probe ZTE sem evidência suficiente em {Endpoint}. confiança={Confidence} nível={Level} modelo={Model}",
                endpoint,
                analysis.Confidence,
                analysis.ConfidenceLevel,
                analysis.Model);

            return AdapterProbeResult.NoMatch(
                AdapterId,
                endpoint,
                Error.Create(
                    ErrorCodes.InsufficientEvidence,
                    "Marcadores públicos insuficientes para identificar um modelo ZTE homologado."));
        }

        var evidence = analysis.Evidence
            .Select(item => new ProbeEvidence("public-html", item))
            .ToList();

        _logger.LogInformation(
            "Probe ZTE identificado em {Endpoint}: fabricante={Manufacturer} modelo={Model} confiança={Confidence}",
            endpoint,
            Manufacturer,
            analysis.Model ?? "não confirmado",
            analysis.Confidence);

        return AdapterProbeResult.Match(
            AdapterId,
            Manufacturer,
            analysis.Model,
            analysis.Confidence,
            endpoint,
            evidence,
            analysis.LoginFormVisible,
            endpoint.Scheme == "https");
    }

    public Task<DeviceIdentityResult> ReadIdentityAsync(
        AuthorizedDeviceSession session,
        CancellationToken cancellationToken)
        => ReadPublicIdentityAsync(session, cancellationToken);

    public Task<DeviceDiagnosticsResult> ReadDiagnosticsAsync(
        AuthorizedDeviceSession session,
        CancellationToken cancellationToken)
    {
        _ = cancellationToken;
        if (!session.IsAuthenticated)
        {
            return Task.FromResult(DeviceDiagnosticsResult.Success(
                DeviceDiagnostics.PublicInterfaceOnly(
                    "PON, temperatura, potência óptica e perfis WAN não estão disponíveis na página pública. " +
                    "O método de autenticação desta firmware ainda não foi mapeado para leitura autenticada neste adaptador de detecção.")));
        }

        return Task.FromResult(DeviceDiagnosticsResult.Unavailable(
            Error.Create(
                ErrorCodes.DiagnosticsRequiresAuthentication,
                "Diagnóstico autenticado é lido pelo adaptador F6201B V9.3.10P8N1 após o login."),
            true));
    }

    public async Task<DeviceCapabilitiesResult> ReadCapabilitiesAsync(
        AuthorizedDeviceSession session,
        CancellationToken cancellationToken)
    {
        var document = await _publicWebReader.GetRootAsync(session.Endpoint, cancellationToken);
        var analysis = ZtePublicPageAnalyzer.Analyze(document?.Title, document?.ServerHeader, document?.Body);

        var capabilities = new DeviceCapabilities(
            PublicWebInterfaceDetected: document is not null,
            HttpsAvailable: session.Endpoint.Scheme == "https",
            HttpAvailable: session.Endpoint.Scheme == "http",
            LoginFormVisible: analysis.LoginFormVisible,
            AuthenticationMapped: session.IsAuthenticated,
            IdentityReadableWithoutLogin: analysis.Model is not null,
            DiagnosticsReadableWithoutLogin: false,
            WriteOperationsSupportedByAdapter: false,
            Notes:
            [
                "Fase 0.1.3-lab: detecção pública e leitura autenticada completa da F6201B V9.3.10P8N1.",
                "WAN, VLAN, PPPoE e TR-069 não são gravados.",
                "F6600P e F670L têm estrutura preparada, sem detector específico nesta entrega.",
                "Gravação desativada por padrão e sem contrato homologado."
            ]);

        return DeviceCapabilitiesResult.Success(capabilities);
    }

    private async Task<DeviceIdentityResult> ReadPublicIdentityAsync(
        AuthorizedDeviceSession session,
        CancellationToken cancellationToken)
    {
        var document = await _publicWebReader.GetRootAsync(session.Endpoint, cancellationToken);
        var analysis = ZtePublicPageAnalyzer.Analyze(document?.Title, document?.ServerHeader, document?.Body);

        if (!analysis.LooksLikeZte)
        {
            return DeviceIdentityResult.Unavailable(
                Error.Create(ErrorCodes.InsufficientEvidence, "Identidade pública ZTE não confirmada."),
                false);
        }

        var identity = new DeviceIdentity(
            Manufacturer,
            analysis.Model,
            FirmwareInfo.Unknown,
            SerialNumber: null,
            MacAddress: null);

        return DeviceIdentityResult.Success(identity) with
        {
            RequiresAuthentication = true
        };
    }
}
