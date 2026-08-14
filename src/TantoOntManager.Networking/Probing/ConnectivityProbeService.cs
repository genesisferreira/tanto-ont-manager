using System.Net;
using System.Net.NetworkInformation;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Network;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Networking.Probing;

public sealed class ConnectivityProbeService : IConnectivityProbeService
{
    private static readonly Regex TitleRegex = new(
        "<title[^>]*>(.*?)</title>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private readonly ILogger<ConnectivityProbeService> _logger;

    public ConnectivityProbeService(ILogger<ConnectivityProbeService> logger)
    {
        _logger = logger;
    }

    public async Task<ConnectivityProbeResult> ProbeAsync(ProbeRequest request, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        ValidateAllowedTarget(request.TargetAddress);

        var icmp = await PingAsync(request.TargetAddress, request.Timeout, cancellationToken);
        var trust = request.TrustLocalCertificate
            ? LocalCertificateTrust.ForSelectedEndpoint(request.TargetAddress)
            : LocalCertificateTrust.Denied(request.TargetAddress);

        var https = await ProbeHttpAsync(
            OntEndpoint.Https(request.TargetAddress),
            trust,
            request.Timeout,
            cancellationToken);

        var http = await ProbeHttpAsync(
            OntEndpoint.Http(request.TargetAddress),
            LocalCertificateTrust.Denied(request.TargetAddress),
            request.Timeout,
            cancellationToken);

        var error = BuildError(icmp.reachable, https, http, request.TrustLocalCertificate);
        var title = https.Title ?? http.Title;
        var server = https.ServerHeader ?? http.ServerHeader;
        var snippet = https.Snippet ?? http.Snippet;
        var tlsNote = https.TlsNote;

        _logger.LogInformation(
            "Probe {Target}: icmp={Icmp} https={Https} http={Http} title={Title}",
            request.TargetAddress,
            icmp.reachable,
            https.Reachable,
            http.Reachable,
            title);

        return new ConnectivityProbeResult(
            https.Reachable ? OntEndpoint.Https(request.TargetAddress) : OntEndpoint.Http(request.TargetAddress),
            icmp.reachable,
            https.Reachable,
            http.Reachable,
            https.StatusCode,
            http.StatusCode,
            title,
            server,
            snippet,
            tlsNote,
            DateTimeOffset.UtcNow - started,
            error);
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

    private async Task<HttpProbeOutcome> ProbeHttpAsync(
        OntEndpoint endpoint,
        LocalCertificateTrust trust,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.All,
            ConnectTimeout = timeout,
            SslOptions =
            {
                RemoteCertificateValidationCallback = (sender, certificate, chain, errors) =>
                    LocalEndpointCertificatePolicy.Validate(trust, endpoint.Address, errors, certificate)
            }
        };

        using var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = timeout
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("TantoOntManager/0.1 (lab-readonly)");

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint.BaseUri);
            using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            var server = response.Headers.Server?.ToString();
            if (string.IsNullOrWhiteSpace(server) && response.Headers.TryGetValues("Server", out var values))
            {
                server = string.Join(' ', values);
            }

            var body = await ReadLimitedBodyAsync(response, 8192, cancellationToken);
            var title = ExtractTitle(body);

            return new HttpProbeOutcome(
                true,
                (int)response.StatusCode,
                title,
                string.IsNullOrWhiteSpace(server) ? null : server,
                Truncate(body, 500),
                endpoint.Scheme == "https" ? DescribeTls(trust, response) : null,
                null);
        }
        catch (OperationCanceledException)
        {
            return HttpProbeOutcome.Failed("timeout");
        }
        catch (HttpRequestException ex) when (IsCertificateError(ex))
        {
            var note = trust.AcceptSelfSignedForSelectedEndpoint
                ? "Falha TLS mesmo com confiança local limitada ao IP selecionado."
                : "Certificado local rejeitado. Marque a opção de confiar no certificado desta ONT para o IP selecionado.";
            return HttpProbeOutcome.Failed(note, note);
        }
        catch (HttpRequestException ex)
        {
            return HttpProbeOutcome.Failed(ex.InnerException?.Message ?? ex.Message);
        }
        catch (AuthenticationException ex)
        {
            return HttpProbeOutcome.Failed(ex.Message, "Falha na validação TLS.");
        }
    }

    private static bool IsCertificateError(HttpRequestException ex)
    {
        var text = (ex.Message + ex.InnerException?.Message) ?? string.Empty;
        return text.Contains("certificate", StringComparison.OrdinalIgnoreCase)
               || text.Contains("SSL", StringComparison.OrdinalIgnoreCase)
               || text.Contains("TLS", StringComparison.OrdinalIgnoreCase)
               || text.Contains("trust", StringComparison.OrdinalIgnoreCase);
    }

    private static string DescribeTls(LocalCertificateTrust trust, HttpResponseMessage response)
        => trust.AcceptSelfSignedForSelectedEndpoint
            ? $"HTTPS {response.Version} com confiança limitada ao IP {trust.SelectedEndpoint}."
            : $"HTTPS {response.Version} com cadeia confiável.";

    private static async Task<string> ReadLimitedBodyAsync(
        HttpResponseMessage response,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[maxBytes];
        var read = await stream.ReadAsync(buffer.AsMemory(0, maxBytes), cancellationToken);
        var charset = response.Content.Headers.ContentType?.CharSet;
        Encoding encoding;
        try
        {
            encoding = string.IsNullOrWhiteSpace(charset) ? Encoding.UTF8 : Encoding.GetEncoding(charset);
        }
        catch (ArgumentException)
        {
            encoding = Encoding.UTF8;
        }

        return encoding.GetString(buffer, 0, read);
    }

    private static string? ExtractTitle(string html)
    {
        var match = TitleRegex.Match(html);
        if (!match.Success)
        {
            return null;
        }

        return System.Net.WebUtility.HtmlDecode(match.Groups[1].Value).Trim();
    }

    private static string Truncate(string text, int length)
        => text.Length <= length ? text : text[..length];

    private static string? BuildError(bool icmp, HttpProbeOutcome https, HttpProbeOutcome http, bool trustLocal)
    {
        if (https.Reachable || http.Reachable)
        {
            return null;
        }

        if (https.TlsNote is not null && !trustLocal)
        {
            return https.Error ?? ErrorCodes.TlsSelfSignedNotAccepted;
        }

        if (!icmp && https.Error is not null)
        {
            return $"ICMP e HTTP/HTTPS sem resposta. {https.Error}";
        }

        return https.Error ?? http.Error ?? (icmp ? "ICMP respondeu, mas a interface web não foi alcançada." : "Sem resposta ICMP, HTTP ou HTTPS.");
    }

    private sealed record HttpProbeOutcome(
        bool Reachable,
        int? StatusCode,
        string? Title,
        string? ServerHeader,
        string? Snippet,
        string? TlsNote,
        string? Error)
    {
        public static HttpProbeOutcome Failed(string error, string? tlsNote = null)
            => new(false, null, null, null, null, tlsNote, error);
    }
}
