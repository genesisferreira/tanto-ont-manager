using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Network;
using TantoOntManager.Networking.Probing;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Networking.Tests;

public sealed class PublicHttpFetcherTests
{
    [Fact]
    public async Task Follows_same_origin_redirect_with_get_only()
    {
        var html = "<html><title>F6201B</title><body>ZTE Corporation Welcome to F6201B</body></html>";
        var handler = new ScriptedHandler();
        handler.Map["https://192.168.100.1/"] = Redirect("https://192.168.100.1/login.html");
        handler.Map["https://192.168.100.1/login.html"] = Html(html);

        var document = await Fetch(handler);
        document.Should().NotBeNull();
        document!.Observation!.RedirectCount.Should().Be(1);
        document.Observation.FinalUri.Should().Be("https://192.168.100.1/login.html");
        document.Title.Should().Be("F6201B");
        handler.Methods.Should().OnlyContain(method => method == "GET");
        handler.Methods.Should().NotContain("POST");
        document.Methods.Should().OnlyContain(method => method == "GET");
    }

    [Fact]
    public async Task Decompresses_gzip_html()
    {
        var html = "<html><title>F6201B</title><body>Welcome to F6201B. ZTE Corporation</body></html>";
        var handler = new ScriptedHandler();
        handler.Map["https://192.168.100.1/"] = Gzip(html);

        var document = await Fetch(handler);
        document.Should().NotBeNull();
        document!.Title.Should().Be("F6201B");
        document.Body.Should().Contain("ZTE Corporation");
        document.Observation!.ContentWasCompressed.Should().BeTrue();
        handler.Methods.Should().OnlyContain(method => method == "GET");
    }

    [Fact]
    public async Task Follows_public_frame_with_get()
    {
        var frameset = File.ReadAllText(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..",
            "TantoOntManager.DeviceAdapters.Zte.Tests", "Fixtures", "zte-f6201b-frameset.html"));
        var login = File.ReadAllText(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..",
            "TantoOntManager.DeviceAdapters.Zte.Tests", "Fixtures", "zte-f6201b-public-real.html"));

        if (!File.Exists(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "TantoOntManager.DeviceAdapters.Zte.Tests", "Fixtures", "zte-f6201b-frameset.html")))
        {
            frameset = "<html><title>F6201B</title><frameset><frame src=\"login.html\" /></frameset></html>";
            login = "<html><body>ZTE Corporation Welcome to F6201B. Please login. F6201B</body></html>";
        }

        var handler = new ScriptedHandler();
        handler.Map["https://192.168.100.1/"] = Html(frameset);
        handler.Map["https://192.168.100.1/login.html"] = Html(login);

        var document = await Fetch(handler);
        document.Should().NotBeNull();
        document!.Body.Should().Contain("Welcome to F6201B");
        document.Observation!.FrameUris.Should().Contain(uri => uri.Contains("login.html", StringComparison.OrdinalIgnoreCase));
        handler.Methods.Should().OnlyContain(method => method == "GET");
    }

    private static async Task<PublicWebDocument?> Fetch(ScriptedHandler handler)
    {
        var fetcher = new PublicHttpFetcher(
            new ProbeSessionSettings { Trust = LocalCertificateTrust.ForSelectedEndpoint(IPAddress.Parse("192.168.100.1")) },
            NullLogger.Instance,
            handler);
        return await fetcher.FetchRootAsync(OntEndpoint.Https(IPAddress.Parse("192.168.100.1")), CancellationToken.None);
    }

    private static HttpResponseMessage Html(string html)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(html, Encoding.UTF8, "text/html")
        };
        return response;
    }

    private static HttpResponseMessage Redirect(string location)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Found);
        response.Headers.Location = new Uri(location);
        response.Content = new StringContent(string.Empty);
        return response;
    }

    private static HttpResponseMessage Gzip(string html)
    {
        using var buffer = new MemoryStream();
        using (var gzip = new GZipStream(buffer, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            var bytes = Encoding.UTF8.GetBytes(html);
            gzip.Write(bytes, 0, bytes.Length);
        }

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(buffer.ToArray())
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/html");
        response.Content.Headers.ContentEncoding.Add("gzip");
        return response;
    }

    private sealed class ScriptedHandler : HttpMessageHandler
    {
        public Dictionary<string, HttpResponseMessage> Map { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Methods { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Methods.Add(request.Method.Method);
            request.Method.Should().Be(HttpMethod.Get);
            var key = request.RequestUri!.ToString();
            if (!Map.TryGetValue(key, out var response))
            {
                throw new InvalidOperationException("Caminho não mapeado: " + key);
            }

            return Task.FromResult(Clone(response));
        }

        private static HttpResponseMessage Clone(HttpResponseMessage original)
        {
            var clone = new HttpResponseMessage(original.StatusCode);
            clone.Headers.Location = original.Headers.Location;
            if (original.Content is StringContent stringContent)
            {
                var text = stringContent.ReadAsStringAsync().GetAwaiter().GetResult();
                clone.Content = new StringContent(text, Encoding.UTF8, original.Content.Headers.ContentType?.MediaType ?? "text/html");
            }
            else
            {
                var bytes = original.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
                clone.Content = new ByteArrayContent(bytes);
                foreach (var encoding in original.Content.Headers.ContentEncoding)
                {
                    clone.Content.Headers.ContentEncoding.Add(encoding);
                }

                if (original.Content.Headers.ContentType is not null)
                {
                    clone.Content.Headers.ContentType = original.Content.Headers.ContentType;
                }
            }

            return clone;
        }
    }
}
