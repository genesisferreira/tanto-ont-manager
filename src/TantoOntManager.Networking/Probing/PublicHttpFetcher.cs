using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Network;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Networking.Probing;

public sealed class PublicProbeCache : IPublicProbeCache
{
    public PublicWebDocument? LastDocument { get; private set; }
    public HttpPublicObservation? LastObservation { get; private set; }

    public void Remember(PublicWebDocument document, HttpPublicObservation? observation)
    {
        LastDocument = document;
        LastObservation = observation ?? document.Observation;
    }
}

public sealed class PublicHttpFetcher
{
    public const int MaxBodyBytes = 524_288;
    private const int MaxRedirects = 5;
    private const int MaxFrames = 3;

    private static readonly Regex TitleRegex = new(
        "<title[^>]*>(.*?)</title>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex FrameRegex = new(
        @"<(?:frame|iframe)\b[^>]*\bsrc\s*=\s*[""']([^""']+)[""']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MetaCharsetRegex = new(
        @"<meta[^>]+charset\s*=\s*[""']?([a-zA-Z0-9._-]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly ProbeSessionSettings _settings;
    private readonly ILogger _logger;
    private readonly HttpMessageHandler? _testHandler;

    public PublicHttpFetcher(ProbeSessionSettings settings, ILogger logger, HttpMessageHandler? testHandler = null)
    {
        _settings = settings;
        _logger = logger;
        _testHandler = testHandler;
    }

    public async Task<PublicWebDocument?> FetchRootAsync(OntEndpoint endpoint, CancellationToken cancellationToken)
    {
        var methods = new List<string>();
        var totalWatch = Stopwatch.StartNew();
        var capture = new RequestCapture();
        var timedOut = false;

        try
        {
            HttpMessageHandler pipeline;
            var disposeHandler = false;
            if (_testHandler is not null)
            {
                pipeline = _testHandler;
            }
            else
            {
                pipeline = CreateSocketsHandler(endpoint, capture);
                disposeHandler = true;
            }

            using var client = new HttpClient(pipeline, disposeHandler)
            {
                Timeout = TimeSpan.FromSeconds(8)
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("TantoOntManager/0.1.1 (lab-readonly)");
            client.DefaultRequestHeaders.AcceptEncoding.ParseAdd("gzip, deflate, br");

            var page = await GetFollowingRedirectsAsync(
                client,
                endpoint.BaseUri,
                endpoint.Address,
                methods,
                cancellationToken);

            if (page is null)
            {
                return null;
            }

            var combined = new StringBuilder();
            combined.AppendLine("<!-- public-root -->");
            combined.AppendLine(page.Body);

            var frameUris = new List<string>();
            foreach (var frameUri in EnumerateSameOriginFrames(page.Body, page.FinalUri).Take(MaxFrames))
            {
                var frame = await GetFollowingRedirectsAsync(
                    client,
                    frameUri,
                    endpoint.Address,
                    methods,
                    cancellationToken);
                if (frame is null)
                {
                    continue;
                }

                frameUris.Add(frame.FinalUri.ToString());
                combined.AppendLine();
                combined.AppendLine($"<!-- public-frame {frame.FinalUri} -->");
                combined.AppendLine(frame.Body);
            }

            var body = combined.ToString();
            var title = ExtractTitle(body) ?? ExtractTitle(page.Body);
            var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
            var contentWasCompressed = page.ContentWasCompressed;
            var observation = new HttpPublicObservation(
                endpoint.Address.ToString(),
                endpoint.Scheme,
                endpoint.Port,
                "GET",
                page.StatusCode,
                page.FinalUri.ToString(),
                page.RedirectCount,
                page.ContentType,
                page.Charset,
                Encoding.UTF8.GetByteCount(body),
                title,
                sha,
                capture.ConnectDuration,
                totalWatch.Elapsed,
                timedOut,
                capture.Certificate,
                contentWasCompressed,
                page.DetectedEncoding,
                page.SafeHeaders,
                frameUris,
                methods);

            _logger.LogInformation(
                "GET público {Target} status={Status} final={Final} redirects={Redirects} bytes={Bytes} hash={Hash} frames={Frames} methods={Methods}",
                endpoint.Address,
                page.StatusCode,
                page.FinalUri,
                page.RedirectCount,
                observation.BodyLengthBytes,
                observation.ShortHash,
                frameUris.Count,
                string.Join(',', methods.Distinct()));

            return new PublicWebDocument(
                endpoint,
                page.StatusCode,
                title,
                page.ServerHeader,
                body,
                observation,
                methods);
        }
        catch (OperationCanceledException)
        {
            timedOut = true;
            _logger.LogWarning("Timeout no GET público de {Target}", endpoint.Address);
            return CreateTimeoutDocument(endpoint, methods, capture.ConnectDuration, totalWatch.Elapsed, capture.Certificate);
        }
        catch (HttpRequestException ex) when (IsCertificateError(ex))
        {
            _logger.LogWarning("TLS no GET público de {Target}: {Category}", endpoint.Address, ClassifyTls(ex));
            return null;
        }
        catch (AuthenticationException ex)
        {
            _logger.LogWarning("Handshake TLS rejeitado em {Target}: {Message}", endpoint.Address, ex.Message);
            return null;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning("Falha de GET público em {Target}: {Message}", endpoint.Address, ex.Message);
            return null;
        }
    }

    private SocketsHttpHandler CreateSocketsHandler(OntEndpoint endpoint, RequestCapture capture)
    {
        return new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            AllowAutoRedirect = false,
            UseCookies = false,
            SslOptions =
            {
                RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    var accepted = LocalEndpointCertificatePolicy.Validate(
                        _settings.Trust,
                        endpoint.Address,
                        errors,
                        cert);
                    capture.Certificate = ToCertificateObservation(cert, errors, accepted);
                    return accepted;
                }
            },
            ConnectCallback = async (context, cancellationToken) =>
            {
                var watch = Stopwatch.StartNew();
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);
                    capture.ConnectDuration = watch.Elapsed;
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

    private async Task<RawPage?> GetFollowingRedirectsAsync(
        HttpClient client,
        Uri start,
        IPAddress allowedAddress,
        List<string> methods,
        CancellationToken cancellationToken)
    {
        var current = start;
        var redirects = 0;
        for (var hop = 0; hop <= MaxRedirects; hop++)
        {
            methods.Add("GET");
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var rawBytes = await ReadLimitedBytesAsync(response, cancellationToken);
            var contentEncoding = response.Content?.Headers.ContentEncoding.ToString() ?? string.Empty;
            var compressed = contentEncoding.Contains("gzip", StringComparison.OrdinalIgnoreCase)
                             || contentEncoding.Contains("deflate", StringComparison.OrdinalIgnoreCase)
                             || contentEncoding.Contains("br", StringComparison.OrdinalIgnoreCase)
                             || LooksLikeGzip(rawBytes);
            var payload = compressed ? DecodeCompressed(rawBytes, contentEncoding) : rawBytes;
            var charset = response.Content?.Headers.ContentType?.CharSet;
            var encodingName = DetectEncodingName(charset, payload);
            var body = DecodeBody(payload, encodingName);
            var status = (int)response.StatusCode;

            if ((int)response.StatusCode is >= 300 and < 400
                && response.Headers.Location is { } location
                && redirects < MaxRedirects)
            {
                var next = location.IsAbsoluteUri ? location : new Uri(current, location);
                if (!IsAllowedPublicUri(next, allowedAddress))
                {
                    _logger.LogWarning("Redirect público ignorado para host não selecionado: {Location}", next.Host);
                    return ToRawPage(response, current, redirects, body, encodingName, compressed, charset);
                }

                current = next;
                redirects++;
                continue;
            }

            return ToRawPage(response, current, redirects, body, encodingName, compressed, charset) with
            {
                StatusCode = status
            };
        }

        return null;
    }

    private static RawPage ToRawPage(
        HttpResponseMessage response,
        Uri finalUri,
        int redirects,
        string body,
        string encodingName,
        bool compressed,
        string? charset)
    {
        var safeHeaders = new List<string>();
        foreach (var header in response.Headers)
        {
            if (IsSensitiveHeader(header.Key))
            {
                continue;
            }

            safeHeaders.Add($"{header.Key}: {string.Join(' ', header.Value)}");
        }

        if (response.Content is not null)
        {
            foreach (var header in response.Content.Headers)
            {
                if (IsSensitiveHeader(header.Key))
                {
                    continue;
                }

                safeHeaders.Add($"{header.Key}: {string.Join(' ', header.Value)}");
            }
        }

        var server = response.Headers.Server?.ToString();
        return new RawPage(
            (int)response.StatusCode,
            finalUri,
            redirects,
            response.Content?.Headers.ContentType?.MediaType,
            charset,
            body,
            string.IsNullOrWhiteSpace(server) ? null : server,
            compressed,
            encodingName,
            safeHeaders);
    }

    private static bool IsSensitiveHeader(string name)
        => name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)
           || name.Equals("WWW-Authenticate", StringComparison.OrdinalIgnoreCase);

    private IEnumerable<Uri> EnumerateSameOriginFrames(string html, Uri baseUri)
    {
        foreach (Match match in FrameRegex.Matches(html))
        {
            var raw = System.Net.WebUtility.HtmlDecode(match.Groups[1].Value).Trim();
            if (raw.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)
                || raw.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
                || raw.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!Uri.TryCreate(baseUri, raw, out var uri))
            {
                continue;
            }

            if (IsAllowedPublicUri(uri, baseUri.Host))
            {
                yield return uri;
            }
        }
    }

    private static bool IsAllowedPublicUri(Uri uri, IPAddress allowedAddress)
        => uri.Scheme is "http" or "https"
           && (uri.Host.Equals(allowedAddress.ToString(), StringComparison.OrdinalIgnoreCase)
               || IPAddress.TryParse(uri.Host, out var parsed) && parsed.Equals(allowedAddress));

    private static bool IsAllowedPublicUri(Uri uri, string originalHost)
        => uri.Scheme is "http" or "https"
           && uri.Host.Equals(originalHost, StringComparison.OrdinalIgnoreCase);

    private static async Task<byte[]> ReadLimitedBytesAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content is null)
        {
            return [];
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        var remaining = MaxBodyBytes;
        while (remaining > 0)
        {
            var read = await stream.ReadAsync(chunk.AsMemory(0, Math.Min(chunk.Length, remaining)), cancellationToken);
            if (read == 0)
            {
                break;
            }

            buffer.Write(chunk, 0, read);
            remaining -= read;
        }

        return buffer.ToArray();
    }

    private static bool LooksLikeGzip(byte[] data)
        => data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B;

    private static byte[] DecodeCompressed(byte[] data, string contentEncoding)
    {
        try
        {
            if (LooksLikeGzip(data) || contentEncoding.Contains("gzip", StringComparison.OrdinalIgnoreCase))
            {
                using var input = new MemoryStream(data);
                using var gzip = new GZipStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                gzip.CopyTo(output);
                return output.ToArray();
            }

            if (contentEncoding.Contains("deflate", StringComparison.OrdinalIgnoreCase))
            {
                using var input = new MemoryStream(data);
                using var deflate = new DeflateStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                deflate.CopyTo(output);
                return output.ToArray();
            }

            if (contentEncoding.Contains("br", StringComparison.OrdinalIgnoreCase))
            {
                using var input = new MemoryStream(data);
                using var brotli = new BrotliStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                brotli.CopyTo(output);
                return output.ToArray();
            }
        }
        catch (InvalidDataException)
        {
            return data;
        }

        return data;
    }

    private static string DetectEncodingName(string? charset, byte[] payload)
    {
        if (!string.IsNullOrWhiteSpace(charset))
        {
            return charset;
        }

        if (payload.Length >= 3 && payload[0] == 0xEF && payload[1] == 0xBB && payload[2] == 0xBF)
        {
            return "utf-8";
        }

        var preview = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 2048));
        var meta = MetaCharsetRegex.Match(preview);
        if (meta.Success)
        {
            return meta.Groups[1].Value;
        }

        return "utf-8";
    }

    private static string DecodeBody(byte[] payload, string encodingName)
    {
        Encoding encoding;
        try
        {
            encoding = Encoding.GetEncoding(encodingName);
        }
        catch (ArgumentException)
        {
            encoding = Encoding.UTF8;
        }

        return encoding.GetString(payload);
    }

    private static string? ExtractTitle(string html)
    {
        var match = TitleRegex.Match(html);
        return match.Success ? System.Net.WebUtility.HtmlDecode(match.Groups[1].Value).Trim() : null;
    }

    private static CertificateObservation ToCertificateObservation(
        X509Certificate? cert,
        SslPolicyErrors errors,
        bool accepted)
    {
        X509Certificate2? cert2 = cert as X509Certificate2 ?? (cert is null ? null : new X509Certificate2(cert));
        var fingerprint = cert2 is null ? null : Convert.ToHexString(SHA256.HashData(cert2.RawData)).ToLowerInvariant();
        var category = errors switch
        {
            SslPolicyErrors.None => TlsErrorCategory.None,
            SslPolicyErrors.RemoteCertificateNotAvailable => TlsErrorCategory.CertificateNotAvailable,
            SslPolicyErrors.RemoteCertificateNameMismatch => TlsErrorCategory.NameMismatch,
            SslPolicyErrors.RemoteCertificateChainErrors => TlsErrorCategory.UntrustedRoot,
            _ => TlsErrorCategory.Other
        };

        return new CertificateObservation(
            cert2?.Subject,
            cert2?.Issuer,
            cert2?.NotBefore.ToUniversalTime(),
            cert2?.NotAfter.ToUniversalTime(),
            fingerprint,
            accepted && errors != SslPolicyErrors.None,
            category);
    }

    private static bool IsCertificateError(HttpRequestException ex)
    {
        var text = ex.Message + ex.InnerException?.Message;
        return text.Contains("certificate", StringComparison.OrdinalIgnoreCase)
               || text.Contains("SSL", StringComparison.OrdinalIgnoreCase)
               || text.Contains("TLS", StringComparison.OrdinalIgnoreCase)
               || text.Contains("trust", StringComparison.OrdinalIgnoreCase);
    }

    private static TlsErrorCategory ClassifyTls(HttpRequestException ex)
        => IsCertificateError(ex) ? TlsErrorCategory.UntrustedRoot : TlsErrorCategory.HandshakeFailed;

    private static PublicWebDocument CreateTimeoutDocument(
        OntEndpoint endpoint,
        List<string> methods,
        TimeSpan connect,
        TimeSpan total,
        CertificateObservation certificate)
    {
        var observation = new HttpPublicObservation(
            endpoint.Address.ToString(),
            endpoint.Scheme,
            endpoint.Port,
            "GET",
            null,
            endpoint.BaseUri.ToString(),
            0,
            null,
            null,
            0,
            null,
            null,
            connect,
            total,
            true,
            certificate,
            false,
            null,
            [],
            [],
            methods);
        return new PublicWebDocument(endpoint, 0, null, null, string.Empty, observation, methods);
    }

    private sealed class RequestCapture
    {
        public TimeSpan ConnectDuration { get; set; }
        public CertificateObservation Certificate { get; set; } = CertificateObservation.None;
    }

    private sealed record RawPage(
        int StatusCode,
        Uri FinalUri,
        int RedirectCount,
        string? ContentType,
        string? Charset,
        string Body,
        string? ServerHeader,
        bool ContentWasCompressed,
        string DetectedEncoding,
        IReadOnlyList<string> SafeHeaders);
}
