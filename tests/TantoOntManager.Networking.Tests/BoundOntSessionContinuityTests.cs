using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Network;
using TantoOntManager.Networking.Probing;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Networking.Tests;

public sealed class BoundOntSessionContinuityTests
{
    private readonly IPAddress _ip = IPAddress.Parse("192.168.100.1");

    [Fact]
    public async Task Login_cookie_is_reused_on_first_authenticated_get_by_same_client()
    {
        var handler = new RecordingHandler();
        MapAuth(handler);
        var transport = Create(handler);
        await transport.GetAsync("/", CancellationToken.None);
        await transport.PostLoginFormAsync(LoginForm(), CancellationToken.None);
        transport.HasSessionCookie.Should().BeTrue();
        transport.SessionToken.Should().NotBeNullOrEmpty();
        var clientId = transport.HttpClientInstanceId;
        clientId.Should().NotBe(0);
        await transport.GetAsync("/", CancellationToken.None);
        transport.HttpClientInstanceId.Should().Be(clientId);
        handler.CookieHeaders.Last().Should().Contain("SID_HTTPS_");
        transport.LoginPostCount.Should().Be(1);
        transport.ConfigPostCount.Should().Be(0);
        transport.SessionToken.Should().NotBeNullOrEmpty();
        transport.SessionToken!.Length.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task New_transport_without_cookie_container_does_not_send_session_cookie()
    {
        var handler = new RecordingHandler();
        MapAuth(handler);
        var first = Create(handler);
        await first.GetAsync(F6201BV9310P8N1AuthContract.LoginPathAndQuery, CancellationToken.None);
        first.HasSessionCookie.Should().BeTrue();

        var second = Create(handler);
        await second.GetAsync("/", CancellationToken.None);
        second.HasSessionCookie.Should().BeFalse();
        second.CookieCount.Should().Be(0);
        handler.CookieHeaders.Last().Should().BeEmpty();
    }

    [Fact]
    public async Task Cleanup_requires_explicit_reason_and_logs_contain_no_secrets()
    {
        var logger = new ListLogger();
        var handler = new RecordingHandler();
        MapAuth(handler);
        var transport = new BoundOntTransport(
            OntEndpoint.Https(_ip),
            "deadbeef",
            new ProbeSessionSettings { Trust = LocalCertificateTrust.ForSelectedEndpoint(_ip) },
            logger,
            handler);

        await transport.GetAsync(F6201BV9310P8N1AuthContract.LoginPathAndQuery, CancellationToken.None);
        transport.ClearCookiesAndState("operador");
        transport.HasSessionCookie.Should().BeFalse();
        transport.LastCleanupReason.Should().Be("operador");
        var joined = string.Join('\n', logger.Messages);
        joined.Should().Contain("motivo=operador");
        joined.Should().NotContain("SID_HTTPS_=memonly");
        joined.Should().NotContain("lab-pass");
        joined.Should().NotContain("cafebabe");
        joined.Should().NotContain("tok2");
        joined.Should().NotContain("memonly");
    }

    private BoundOntTransport Create(RecordingHandler handler)
        => new(
            OntEndpoint.Https(_ip),
            "deadbeef",
            new ProbeSessionSettings { Trust = LocalCertificateTrust.ForSelectedEndpoint(_ip) },
            NullLogger.Instance,
            handler);

    private static Dictionary<string, string> LoginForm()
        => new()
        {
            ["action"] = "login",
            ["Username"] = "u",
            ["Password"] = "hash",
            ["_sessionTOKEN"] = "tok"
        };

    private static void MapAuth(RecordingHandler handler)
    {
        handler.Map["https://192.168.100.1/"] = Html("<html>ok</html>");
        handler.Map["https://192.168.100.1/?_type=loginData&_tag=login_entry"] = Json(
            """{"sess_token":"tok","loginErrMsg":"","promptMsg":"","lockingTime":0}""",
            setCookie: true);
        handler.PostMap["https://192.168.100.1/?_type=loginData&_tag=login_entry"] = Json(
            """{"login_need_refresh":true,"sess_token":"tok2","loginErrMsg":"","promptMsg":""}""",
            setCookie: true);
    }

    private static HttpResponseMessage Html(string html)
        => new(HttpStatusCode.OK) { Content = new StringContent(html, Encoding.UTF8, "text/html") };

    private static HttpResponseMessage Json(string json, bool setCookie = false)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        if (setCookie)
        {
            response.Headers.TryAddWithoutValidation("Set-Cookie", "SID_HTTPS_=memonly; Path=/; HttpOnly; Secure");
        }

        return response;
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public Dictionary<string, HttpResponseMessage> Map { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, HttpResponseMessage> PostMap { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> CookieHeaders { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CookieHeaders.Add(request.Headers.TryGetValues("Cookie", out var values) ? string.Join("; ", values) : string.Empty);
            var key = request.RequestUri!.ToString();
            if (request.Method == HttpMethod.Post && PostMap.TryGetValue(key, out var post))
            {
                return Task.FromResult(Clone(post));
            }

            return Task.FromResult(Clone(Map[key]));
        }

        private static HttpResponseMessage Clone(HttpResponseMessage original)
        {
            var clone = new HttpResponseMessage(original.StatusCode);
            foreach (var header in original.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            var text = original.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            clone.Content = new StringContent(text, Encoding.UTF8, original.Content.Headers.ContentType?.MediaType ?? "text/html");
            return clone;
        }
    }

    private sealed class ListLogger : ILogger
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Messages.Add(formatter(state, exception));
    }
}
