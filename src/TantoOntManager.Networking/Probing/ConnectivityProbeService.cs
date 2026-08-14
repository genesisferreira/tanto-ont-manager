using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Network;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Networking.Probing;

public sealed class ConnectivityProbeService : IConnectivityProbeService
{
    private readonly ProbeSessionSettings _settings;
    private readonly IPublicProbeCache _cache;
    private readonly ILogger<ConnectivityProbeService> _logger;

    public ConnectivityProbeService(
        ProbeSessionSettings settings,
        IPublicProbeCache cache,
        ILogger<ConnectivityProbeService> logger)
    {
        _settings = settings;
        _cache = cache;
        _logger = logger;
    }

    public async Task<ConnectivityProbeResult> ProbeAsync(ProbeRequest request, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        ValidateAllowedTarget(request.TargetAddress);

        var icmp = await PingAsync(request.TargetAddress, request.Timeout, cancellationToken);
        _settings.Trust = request.TrustLocalCertificate
            ? LocalCertificateTrust.ForSelectedEndpoint(request.TargetAddress)
            : LocalCertificateTrust.Denied(request.TargetAddress);

        var fetcher = new PublicHttpFetcher(_settings, _logger);
        var httpsDocument = await fetcher.FetchRootAsync(OntEndpoint.Https(request.TargetAddress), cancellationToken);
        var httpDocument = await fetcher.FetchRootAsync(OntEndpoint.Http(request.TargetAddress), cancellationToken);

        if (httpsDocument is not null)
        {
            _cache.Remember(httpsDocument, httpsDocument.Observation);
        }
        else if (httpDocument is not null)
        {
            _cache.Remember(httpDocument, httpDocument.Observation);
        }

        var https = httpsDocument?.Observation;
        var http = httpDocument?.Observation;
        var httpsOk = httpsDocument is not null && httpsDocument.StatusCode is > 0 and < 600;
        var httpOk = httpDocument is not null && httpDocument.StatusCode is > 0 and < 600;
        var title = https?.Title ?? http?.Title ?? httpsDocument?.Title ?? httpDocument?.Title;
        var server = httpsDocument?.ServerHeader ?? httpDocument?.ServerHeader;
        var tlsNote = DescribeTls(https);
        var error = BuildError(icmp.reachable, httpsOk, httpOk, https, request.TrustLocalCertificate);

        _logger.LogInformation(
            "Probe {Target}: icmp={Icmp} https={Https} http={Http} title={Title} httpsStatus={HttpsStatus} hash={Hash}",
            request.TargetAddress,
            icmp.reachable,
            httpsOk,
            httpOk,
            title,
            https?.StatusCode,
            https?.ShortHash ?? http?.ShortHash);

        return new ConnectivityProbeResult(
            httpsOk ? OntEndpoint.Https(request.TargetAddress) : OntEndpoint.Http(request.TargetAddress),
            icmp.reachable,
            httpsOk,
            httpOk,
            https?.StatusCode,
            http?.StatusCode,
            title,
            server,
            null,
            tlsNote,
            DateTimeOffset.UtcNow - started,
            error,
            https,
            http);
    }

    private static void ValidateAllowedTarget(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.Broadcast))
        {
            throw new InvalidOperationException("O alvo de probe não é um endereço ONT permitido.");
        }
    }

    private static async Task<(bool reachable, string? error)> PingAsync(
        IPAddress address,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(address, (int)Math.Clamp(timeout.TotalMilliseconds, 1, int.MaxValue));
            return (reply.Status == IPStatus.Success, reply.Status == IPStatus.Success ? null : reply.Status.ToString());
        }
        catch (OperationCanceledException)
        {
            return (false, ErrorCodes.ProbeTimeout);
        }
        catch (PingException ex)
        {
            return (false, ex.Message);
        }
    }

    private static string? DescribeTls(HttpPublicObservation? https)
    {
        if (https is null)
        {
            return null;
        }

        var cert = https.Certificate;
        return $"TLS {cert.ErrorCategory}; subject={cert.Subject ?? "—"}; issuer={cert.Issuer ?? "—"}; localException={cert.AcceptedByLocalException}";
    }

    private static string? BuildError(
        bool icmp,
        bool httpsOk,
        bool httpOk,
        HttpPublicObservation? https,
        bool trustLocal)
    {
        if (httpsOk || httpOk)
        {
            return null;
        }

        if (https?.TimedOut == true)
        {
            return ErrorCodes.ProbeTimeout;
        }

        if (!trustLocal && https?.Certificate.ErrorCategory is not TlsErrorCategory.None)
        {
            return ErrorCodes.TlsSelfSignedNotAccepted;
        }

        return icmp
            ? "ICMP respondeu, mas a interface web não foi alcançada."
            : "Sem resposta ICMP, HTTP ou HTTPS.";
    }
}
