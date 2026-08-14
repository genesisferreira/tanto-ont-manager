using Microsoft.Extensions.Logging;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Network;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Networking.Probing;

public sealed class HttpPublicWebReader : IPublicWebReader
{
    private readonly ProbeSessionSettings _settings;
    private readonly IPublicProbeCache _cache;
    private readonly ILogger<HttpPublicWebReader> _logger;

    public HttpPublicWebReader(
        ProbeSessionSettings settings,
        IPublicProbeCache cache,
        ILogger<HttpPublicWebReader> logger)
    {
        _settings = settings;
        _cache = cache;
        _logger = logger;
    }

    public async Task<PublicWebDocument?> GetRootAsync(OntEndpoint endpoint, CancellationToken cancellationToken)
    {
        if (_cache.LastDocument is { } cached
            && cached.Endpoint.Address.Equals(endpoint.Address)
            && cached.Endpoint.Scheme == endpoint.Scheme)
        {
            return cached;
        }

        var fetcher = new PublicHttpFetcher(_settings, _logger);
        var document = await fetcher.FetchRootAsync(endpoint, cancellationToken);
        if (document is not null)
        {
            _cache.Remember(document, document.Observation);
        }

        return document;
    }
}
