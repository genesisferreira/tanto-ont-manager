using System.Security.Authentication;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Network;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Networking.Probing;

public sealed class HttpPublicWebReader : IPublicWebReader
{
    private static readonly Regex TitleRegex = new(
        "<title[^>]*>(.*?)</title>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private readonly ProbeSessionSettings _settings;
    private readonly ILogger<HttpPublicWebReader> _logger;

    public HttpPublicWebReader(ProbeSessionSettings settings, ILogger<HttpPublicWebReader> logger)
    {
        _settings = settings;
        _logger = logger;
    }

    public async Task<PublicWebDocument?> GetRootAsync(OntEndpoint endpoint, CancellationToken cancellationToken)
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(3),
            SslOptions =
            {
                RemoteCertificateValidationCallback = (sender, certificate, chain, errors) =>
                    LocalEndpointCertificatePolicy.Validate(_settings.Trust, endpoint.Address, errors, certificate)
            }
        };

        using var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(3)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("TantoOntManager/0.1 (lab-readonly)");

        try
        {
            using var response = await client.GetAsync(endpoint.BaseUri, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (body.Length > 32_768)
            {
                body = body[..32_768];
            }

            var titleMatch = TitleRegex.Match(body);
            var title = titleMatch.Success
                ? System.Net.WebUtility.HtmlDecode(titleMatch.Groups[1].Value).Trim()
                : null;

            var server = response.Headers.Server?.ToString();
            _logger.LogInformation("Leitura pública de {Endpoint} status={Status}", endpoint, (int)response.StatusCode);

            return new PublicWebDocument(endpoint, (int)response.StatusCode, title, string.IsNullOrWhiteSpace(server) ? null : server, body);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning("Falha ao ler a raiz pública de {Endpoint}: {Message}", endpoint, ex.Message);
            return null;
        }
        catch (AuthenticationException ex)
        {
            _logger.LogWarning("TLS rejeitado em {Endpoint}: {Message}", endpoint, ex.Message);
            return null;
        }
    }
}
