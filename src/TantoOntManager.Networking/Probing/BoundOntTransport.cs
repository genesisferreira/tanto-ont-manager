using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Network;
using TantoOntManager.Security.Export;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Networking.Probing;

public sealed class BoundOntTransportFactory : IBoundOntTransportFactory
{
    private readonly ProbeSessionSettings _settings;
    private readonly ILogger<BoundOntTransport> _logger;
    private readonly HttpMessageHandler? _testHandler;

    public BoundOntTransportFactory(
        ProbeSessionSettings settings,
        ILogger<BoundOntTransport> logger,
        HttpMessageHandler? testHandler = null)
    {
        _settings = settings;
        _logger = logger;
        _testHandler = testHandler;
    }

    public IBoundOntTransport Create(OntEndpoint endpoint, string? pinnedCertificateSha256)
        => new BoundOntTransport(endpoint, pinnedCertificateSha256, _settings, _logger, _testHandler);
}

public sealed class BoundOntTransport : IBoundOntTransport
{
    private const int MaxRedirects = 5;
    private readonly OntEndpoint _endpoint;
    private readonly ProbeSessionSettings _settings;
    private readonly ILogger _logger;
    private readonly HttpMessageHandler? _testHandler;
    private readonly CookieContainer _cookies = new();
    private readonly List<string> _methods = [];
    private readonly List<string> _gets = [];
    private readonly List<string> _posts = [];
    private readonly HashSet<string> _discoveredTags = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private bool _disposed;

    public BoundOntTransport(
        OntEndpoint endpoint,
        string? pinnedCertificateSha256,
        ProbeSessionSettings settings,
        ILogger logger,
        HttpMessageHandler? testHandler = null)
    {
        _endpoint = endpoint;
        ObservedCertificateSha256 = pinnedCertificateSha256;
        _settings = settings;
        _logger = logger;
        _testHandler = testHandler;
        BoundAddress = endpoint.Address;
    }

    public IPAddress BoundAddress { get; }

    public string? ObservedCertificateSha256 { get; private set; }

    public bool HasSessionCookie
    {
        get
        {
            lock (_gate)
            {
                return _cookies.GetCookies(_endpoint.BaseUri)
                    .Cast<Cookie>()
                    .Any(item => item.Name.StartsWith(F6201BV9310P8N1AuthContract.SessionCookieNamePrefix, StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    public int PostCount => LoginPostCount + LogoutPostCount;

    public int LoginPostCount { get; private set; }

    public int LogoutPostCount { get; private set; }

    public int ConfigPostCount => 0;

    public string? SessionToken { get; private set; }

    public IReadOnlyList<string> HttpMethodsUsed
    {
        get
        {
            lock (_gate)
            {
                return _methods.ToList();
            }
        }
    }

    public IReadOnlyList<string> MaskedGetPages
    {
        get
        {
            lock (_gate)
            {
                return _gets.ToList();
            }
        }
    }

    public IReadOnlyList<string> MaskedPosts
    {
        get
        {
            lock (_gate)
            {
                return _posts.ToList();
            }
        }
    }

    public async Task<BoundHttpResult> GetAsync(string pathAndQuery, CancellationToken cancellationToken)
    {
        if (!TryCreateUri(pathAndQuery, out var uri, out var error))
        {
            return BoundHttpResult.Fail(error!);
        }

        if (!F6201BV9310P8N1AuthContract.IsAllowedGet(uri, BoundAddress, _discoveredTags))
        {
            _logger.LogWarning("GET recusado fora da allowlist: {Path}", F6201BV9310P8N1AuthContract.MaskUri(uri));
            return BoundHttpResult.Fail(Error.Create(
                ErrorCodes.GetNotAllowlisted,
                "GET autenticado recusado: o caminho não está na allowlist desta firmware."));
        }

        return await SendAsync(HttpMethod.Get, uri, null, cancellationToken);
    }

    public async Task<BoundHttpResult> PostLoginFormAsync(
        IReadOnlyDictionary<string, string> form,
        CancellationToken cancellationToken)
    {
        if (!TryCreateUri(F6201BV9310P8N1AuthContract.LoginPathAndQuery, out var uri, out var error))
        {
            return BoundHttpResult.Fail(error!);
        }

        if (!F6201BV9310P8N1AuthContract.IsLoginPost(uri, BoundAddress))
        {
            return BoundHttpResult.Fail(Error.Create(
                ErrorCodes.PostNotAllowed,
                "POST recusado: somente o endpoint de login homologado pode receber POST."));
        }

        if (LoginPostCount >= 1)
        {
            return BoundHttpResult.Fail(Error.Create(
                ErrorCodes.PostNotAllowed,
                "POST recusado: o login já foi enviado nesta tentativa e não é repetido automaticamente."));
        }

        var content = new FormUrlEncodedContent(form);
        return await SendAsync(HttpMethod.Post, uri, content, cancellationToken);
    }

    public async Task<BoundHttpResult> PostLogoutFormAsync(
        IReadOnlyDictionary<string, string> form,
        CancellationToken cancellationToken)
    {
        if (!TryCreateUri(F6201BV9310P8N1AuthContract.LogoutPathAndQuery, out var uri, out var error))
        {
            return BoundHttpResult.Fail(error!);
        }

        if (!F6201BV9310P8N1AuthContract.IsLogoutPost(uri, BoundAddress))
        {
            return BoundHttpResult.Fail(Error.Create(
                ErrorCodes.LogoutNotAllowlisted,
                "POST recusado: somente o endpoint de logout observado na interface pode ser usado."));
        }

        if (LogoutPostCount >= 1)
        {
            return BoundHttpResult.Fail(Error.Create(
                ErrorCodes.PostNotAllowed,
                "POST recusado: o logout já foi enviado nesta sessão."));
        }

        var content = new FormUrlEncodedContent(form);
        return await SendAsync(HttpMethod.Post, uri, content, cancellationToken);
    }

    public void RememberSafeRead(string type, string tag)
    {
        if (!F6201BV9310P8N1AuthContract.IsAllowedGetType(type)
            || !F6201BV9310P8N1AuthContract.IsValidTag(tag)
            || F6201BV9310P8N1AuthContract.IsDestructiveTag(tag)
            || F6201BV9310P8N1AuthContract.IsAuthControlTag(tag))
        {
            return;
        }

        _discoveredTags.Add(F6201BV9310P8N1AuthContract.MakeKey(type, tag));
    }

    public void RememberDiscoveredTags(string html)
    {
        foreach (var item in F6201BSafeReadDiscovery.Discover(html))
        {
            if (item.Classification == SafeReadClassification.SafeRead)
            {
                _discoveredTags.Add(item.TypeAndTag);
            }
        }
    }

    public void ClearCookiesAndState()
    {
        lock (_gate)
        {
            foreach (Cookie cookie in _cookies.GetCookies(_endpoint.BaseUri))
            {
                cookie.Expired = true;
            }

            SessionToken = null;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ClearCookiesAndState();
    }

    public void DiscoverFrom(string html) => RememberDiscoveredTags(html);

    private async Task<BoundHttpResult> SendAsync(
        HttpMethod method,
        Uri start,
        HttpContent? content,
        CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        var current = start;
        var redirects = 0;
        HttpMessageHandler pipeline;
        var disposeHandler = false;
        if (_testHandler is not null)
        {
            pipeline = new CookieAwareHandler(_cookies, _testHandler);
            disposeHandler = true;
        }
        else
        {
            pipeline = CreateHandler();
            disposeHandler = true;
        }

        using var client = new HttpClient(pipeline, disposeHandler)
        {
            Timeout = TimeSpan.FromSeconds(8)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("TantoOntManager/0.1.3 (lab-readonly)");
        client.DefaultRequestHeaders.CacheControl = new CacheControlHeaderValue { NoCache = true };

        try
        {
            for (var hop = 0; hop <= MaxRedirects; hop++)
            {
                using var request = new HttpRequestMessage(method, current);
                if (content is not null && hop == 0)
                {
                    request.Content = content;
                }

                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var body = await ReadBodyAsync(response, cancellationToken);
                var status = (int)response.StatusCode;

                if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
                {
                    var next = location.IsAbsoluteUri ? location : new Uri(current, location);
                    if (!next.Host.Equals(BoundAddress.ToString(), StringComparison.OrdinalIgnoreCase))
                    {
                        Record(method, current, isPost: method == HttpMethod.Post);
                        return BoundHttpResult.Fail(
                            Error.Create(
                                ErrorCodes.RedirectForeignHost,
                                "Redirect para outro host foi recusado."),
                            status,
                            watch.Elapsed,
                            redirects + 1);
                    }

                    if (method == HttpMethod.Post)
                    {
                        Record(method, current, isPost: true);
                        return BoundHttpResult.Fail(
                            Error.Create(
                                ErrorCodes.UnexpectedRedirect,
                                "Redirect inesperado após o POST de login."),
                            status,
                            watch.Elapsed,
                            redirects + 1);
                    }

                    if (!F6201BV9310P8N1AuthContract.IsAllowedGet(next, BoundAddress, _discoveredTags))
                    {
                        Record(method, current, isPost: false);
                        return BoundHttpResult.Fail(
                            Error.Create(
                                ErrorCodes.UnexpectedRedirect,
                                "Redirect para caminho não homologado foi recusado."),
                            status,
                            watch.Elapsed,
                            redirects + 1);
                    }

                    current = next;
                    redirects++;
                    method = HttpMethod.Get;
                    content = null;
                    continue;
                }

                Record(method, current, isPost: method == HttpMethod.Post);
                if (method == HttpMethod.Post)
                {
                    if (F6201BV9310P8N1AuthContract.IsLoginPost(current, BoundAddress))
                    {
                        LoginPostCount++;
                    }
                    else if (F6201BV9310P8N1AuthContract.IsLogoutPost(current, BoundAddress))
                    {
                        LogoutPostCount++;
                    }
                }

                RememberDiscoveredTags(body);
                CaptureSessionToken(body);
                var hash = AuthenticatedPayloadSanitizer.Sha256Short(body);
                _logger.LogInformation(
                    "HTTP autenticado method={Method} path={Path} status={Status} redirects={Redirects} hash={Hash} posts={Posts}",
                    method.Method,
                    F6201BV9310P8N1AuthContract.MaskUri(current),
                    status,
                    redirects,
                    hash,
                    PostCount);

                return new BoundHttpResult(
                    true,
                    status,
                    body,
                    response.Content.Headers.ContentType?.MediaType,
                    current.ToString(),
                    redirects,
                    hash,
                    watch.Elapsed,
                    null);
            }

            return BoundHttpResult.Fail(
                Error.Create(ErrorCodes.UnexpectedRedirect, "Limite de redirects excedido."),
                0,
                watch.Elapsed,
                redirects);
        }
        catch (OperationCanceledException)
        {
            return BoundHttpResult.Fail(
                Error.Create(ErrorCodes.ProbeTimeout, "A requisição autenticada excedeu o tempo limite."),
                0,
                watch.Elapsed);
        }
        catch (AuthenticationException)
        {
            return BoundHttpResult.Fail(
                Error.Create(ErrorCodes.CertificateChanged, "O certificado TLS mudou ou foi rejeitado durante a sessão."),
                0,
                watch.Elapsed);
        }
        catch (HttpRequestException ex) when (ex.Message.Contains("certificado", StringComparison.OrdinalIgnoreCase)
                                              || ex.Message.Contains("certificate", StringComparison.OrdinalIgnoreCase)
                                              || ex.Message.Contains("fingerprint", StringComparison.OrdinalIgnoreCase))
        {
            return BoundHttpResult.Fail(
                Error.Create(ErrorCodes.CertificateChanged, "O certificado TLS observado não coincide com a sessão."),
                0,
                watch.Elapsed);
        }
        catch (HttpRequestException)
        {
            return BoundHttpResult.Fail(
                Error.Create(ErrorCodes.HttpProbeFailed, "Falha HTTP controlada na sessão autenticada."),
                0,
                watch.Elapsed);
        }
    }

    private HttpMessageHandler CreateHandler()
    {
        return new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            AllowAutoRedirect = false,
            UseCookies = true,
            CookieContainer = _cookies,
            SslOptions =
            {
                RemoteCertificateValidationCallback = (_, cert, _, errors) =>
                {
                    var accepted = LocalEndpointCertificatePolicy.Validate(
                        _settings.Trust,
                        BoundAddress,
                        errors,
                        cert);
                    if (!accepted || cert is null)
                    {
                        return false;
                    }

                    var fingerprint = Convert.ToHexString(SHA256.HashData(new X509Certificate2(cert).RawData)).ToLowerInvariant();
                    if (string.IsNullOrWhiteSpace(ObservedCertificateSha256))
                    {
                        ObservedCertificateSha256 = fingerprint;
                        return true;
                    }

                    if (!ObservedCertificateSha256.Equals(fingerprint, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new AuthenticationException("fingerprint-mismatch");
                    }

                    return true;
                }
            },
            ConnectCallback = async (context, cancellationToken) =>
            {
                if (!IPAddress.TryParse(context.DnsEndPoint.Host, out var host)
                    || !host.Equals(BoundAddress))
                {
                    throw new InvalidOperationException("A sessão autenticada não pode ser reutilizada em outro IP.");
                }

                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };
    }

    private void Record(HttpMethod method, Uri uri, bool isPost)
    {
        var masked = F6201BV9310P8N1AuthContract.MaskUri(uri);
        lock (_gate)
        {
            _methods.Add(method.Method);
            if (isPost)
            {
                _posts.Add(masked);
            }
            else
            {
                _gets.Add(masked);
            }
        }
    }

    private bool TryCreateUri(string pathAndQuery, out Uri uri, out Error? error)
    {
        uri = null!;
        error = null;
        if (!Uri.TryCreate(_endpoint.BaseUri, pathAndQuery, out uri!))
        {
            error = Error.Create(ErrorCodes.GetNotAllowlisted, "Caminho HTTP inválido.");
            return false;
        }

        if (!uri.Host.Equals(BoundAddress.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            error = Error.Create(ErrorCodes.RedirectForeignHost, "A sessão autenticada não pode ser reutilizada em outro IP.");
            return false;
        }

        return true;
    }

    private void CaptureSessionToken(string body)
    {
        var token = F6201BHtmlText.ReadSessionToken(body);
        if (!string.IsNullOrWhiteSpace(token))
        {
            SessionToken = token;
        }
    }

    private static async Task<string> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        if (bytes.Length > PublicHttpFetcher.MaxBodyBytes)
        {
            bytes = bytes[..PublicHttpFetcher.MaxBodyBytes];
        }

        return Encoding.UTF8.GetString(bytes);
    }
}

internal sealed class CookieAwareHandler : DelegatingHandler
{
    private readonly CookieContainer _cookies;

    public CookieAwareHandler(CookieContainer cookies, HttpMessageHandler inner)
        : base(inner)
    {
        _cookies = cookies;
    }

    protected override void Dispose(bool disposing)
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request.RequestUri is { } uri)
        {
            var header = _cookies.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.Remove("Cookie");
                request.Headers.TryAddWithoutValidation("Cookie", header);
            }
        }

        var response = await base.SendAsync(request, cancellationToken);
        if (request.RequestUri is { } responseUri
            && response.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            foreach (var cookie in cookies)
            {
                try
                {
                    _cookies.SetCookies(responseUri, cookie);
                }
                catch (CookieException)
                {
                }
            }
        }

        return response;
    }
}
