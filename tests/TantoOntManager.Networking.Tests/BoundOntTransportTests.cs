using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Network;
using TantoOntManager.Networking.Probing;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Networking.Tests;

public sealed class BoundOntTransportTests
{
    private readonly IPAddress _ip = IPAddress.Parse("192.168.100.1");

    [Fact]
    public async Task Logout_post_is_allowed_once_after_login()
    {
        var handler = new ScriptedHandler();
        MapDefaults(handler);
        handler.PostMap["https://192.168.100.1/?_type=loginData&_tag=logout_entry"] = Json(
            """{"need_refresh":true}""",
            setCookie: false);
        var transport = Create(handler);
        await transport.GetAsync("/", CancellationToken.None);
        await transport.PostLoginFormAsync(LoginForm(), CancellationToken.None);
        var first = await transport.PostLogoutFormAsync(new Dictionary<string, string>
        {
            ["IF_LogOff"] = "1",
            ["_sessionTOKEN"] = "tok"
        }, CancellationToken.None);
        var second = await transport.PostLogoutFormAsync(new Dictionary<string, string>
        {
            ["IF_LogOff"] = "1",
            ["_sessionTOKEN"] = "tok"
        }, CancellationToken.None);

        first.Succeeded.Should().BeTrue();
        second.Succeeded.Should().BeFalse();
        handler.Posts.Should().HaveCount(2);
        handler.Posts[0].Should().Contain("login_entry");
        handler.Posts[1].Should().Contain("logout_entry");
        transport.LoginPostCount.Should().Be(1);
        transport.LogoutPostCount.Should().Be(1);
        transport.ConfigPostCount.Should().Be(0);
    }

    [Fact]
    public async Task Hidden_data_is_allowlisted_only_when_discovered()
    {
        var handler = new ScriptedHandler();
        MapDefaults(handler);
        handler.Map["https://192.168.100.1/"] = Html("<script>var x=\"/?_type=hiddenData&_tag=sntp_data\";</script>");
        handler.Map["https://192.168.100.1/?_type=hiddenData&_tag=sntp_data"] = Html("time");
        var transport = Create(handler);
        await transport.GetAsync("/", CancellationToken.None);
        var allowed = await transport.GetAsync("/?_type=hiddenData&_tag=sntp_data", CancellationToken.None);
        var unknown = await transport.GetAsync("/?_type=hiddenData&_tag=unknown_data", CancellationToken.None);
        allowed.Succeeded.Should().BeTrue();
        unknown.Succeeded.Should().BeFalse();
        unknown.Error!.Code.Should().Be(ErrorCodes.GetNotAllowlisted);
    }

    [Fact]
    public async Task Login_post_is_only_allowed_endpoint_and_happens_once()
    {
        var handler = new ScriptedHandler();
        MapDefaults(handler);
        var transport = Create(handler);

        await transport.GetAsync("/", CancellationToken.None);
        var first = await transport.PostLoginFormAsync(LoginForm(), CancellationToken.None);
        var second = await transport.PostLoginFormAsync(LoginForm(), CancellationToken.None);

        first.Succeeded.Should().BeTrue();
        second.Succeeded.Should().BeFalse();
        second.Error!.Code.Should().Be(ErrorCodes.PostNotAllowed);
        handler.Posts.Should().HaveCount(1);
        handler.Posts[0].Should().Contain("_tag=login_entry");
        handler.Methods.Count(item => item == "POST").Should().Be(1);
    }

    [Fact]
    public async Task Cookies_stay_in_memory_and_clear()
    {
        var handler = new ScriptedHandler();
        MapDefaults(handler);
        var transport = Create(handler);

        await transport.GetAsync(F6201BV9310P8N1AuthContract.LoginPathAndQuery, CancellationToken.None);
        transport.HasSessionCookie.Should().BeTrue();
        transport.ClearCookiesAndState();
        transport.HasSessionCookie.Should().BeFalse();
    }

    [Fact]
    public async Task Get_outside_allowlist_is_blocked()
    {
        var handler = new ScriptedHandler();
        MapDefaults(handler);
        var transport = Create(handler);
        var result = await transport.GetAsync("/apply.cgi", CancellationToken.None);
        result.Succeeded.Should().BeFalse();
        result.Error!.Code.Should().Be(ErrorCodes.GetNotAllowlisted);
        handler.Methods.Should().BeEmpty();
    }

    [Fact]
    public async Task Destructive_menu_is_not_allowlisted()
    {
        var handler = new ScriptedHandler();
        MapDefaults(handler);
        handler.Map["https://192.168.100.1/"] = Html("<a MenuPage='devinfo'>info</a><a MenuPage='reboot'>Reboot</a>");
        var transport = Create(handler);
        await transport.GetAsync("/", CancellationToken.None);
        var blocked = await transport.GetAsync("/?_type=menuView&_tag=reboot", CancellationToken.None);
        blocked.Error!.Code.Should().Be(ErrorCodes.GetNotAllowlisted);
        var allowed = await transport.GetAsync("/?_type=menuView&_tag=devinfo", CancellationToken.None);
        allowed.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task Foreign_host_redirect_is_rejected()
    {
        var handler = new ScriptedHandler();
        handler.Map["https://192.168.100.1/"] = Redirect("https://example.com/");
        var transport = Create(handler);
        var result = await transport.GetAsync("/", CancellationToken.None);
        result.Error!.Code.Should().Be(ErrorCodes.RedirectForeignHost);
    }

    [Fact]
    public async Task Unexpected_redirect_after_login_post_is_rejected()
    {
        var handler = new ScriptedHandler();
        MapDefaults(handler);
        handler.Map["https://192.168.100.1/?_type=loginData&_tag=login_entry"] = Redirect("https://192.168.100.1/other");
        handler.PostMap["https://192.168.100.1/?_type=loginData&_tag=login_entry"] = Redirect("https://192.168.100.1/other");
        var transport = Create(handler);
        await transport.GetAsync("/", CancellationToken.None);
        var result = await transport.PostLoginFormAsync(LoginForm(), CancellationToken.None);
        result.Error!.Code.Should().Be(ErrorCodes.UnexpectedRedirect);
    }

    [Fact]
    public async Task Timeout_is_typed()
    {
        var handler = new ScriptedHandler();
        handler.Map["https://192.168.100.1/"] = Html("ok");
        var transport = Create(handler);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var result = await transport.GetAsync("/", cts.Token);
        result.Succeeded.Should().BeFalse();
        result.Error.Should().NotBeNull();
        result.Error!.Code.Should().Be(ErrorCodes.ProbeTimeout);
    }

    [Fact]
    public void Session_cannot_target_another_ip()
    {
        var uri = new Uri("https://192.168.1.1/");
        F6201BV9310P8N1AuthContract.IsAllowedGet(uri, _ip, []).Should().BeFalse();
        F6201BV9310P8N1AuthContract.IsLoginPost(uri, _ip).Should().BeFalse();
    }

    private BoundOntTransport Create(ScriptedHandler handler)
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

    private static void MapDefaults(ScriptedHandler handler)
    {
        handler.Map["https://192.168.100.1/"] = Html("<html>ok</html>");
        handler.Map["https://192.168.100.1/?_type=loginData&_tag=login_entry"] = Json(
            """{"sess_token":"tok","loginErrMsg":"","promptMsg":"","lockingTime":0}""",
            setCookie: true);
        handler.Map["https://192.168.100.1/?_type=loginData&_tag=login_token"] = Xml("<ajax_response_xml_root>cafebabe</ajax_response_xml_root>");
        handler.Map["https://192.168.100.1/?_type=menuView&_tag=devinfo"] = Html("Hardware Version: V9.3.12");
        handler.PostMap["https://192.168.100.1/?_type=loginData&_tag=login_entry"] = Json(
            """{"login_need_refresh":true,"loginErrMsg":"","promptMsg":""}""",
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

    private static HttpResponseMessage Xml(string xml)
        => new(HttpStatusCode.OK) { Content = new StringContent(xml, Encoding.UTF8, "text/xml") };

    private static HttpResponseMessage Redirect(string location)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Found);
        response.Headers.Location = new Uri(location);
        response.Content = new StringContent(string.Empty);
        return response;
    }

    private sealed class ScriptedHandler : HttpMessageHandler
    {
        public Dictionary<string, HttpResponseMessage> Map { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, HttpResponseMessage> PostMap { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Methods { get; } = [];
        public List<string> Posts { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Methods.Add(request.Method.Method);
            var key = request.RequestUri!.ToString();
            if (request.Method == HttpMethod.Post)
            {
                Posts.Add(key);
                if (PostMap.TryGetValue(key, out var post))
                {
                    return Task.FromResult(Clone(post));
                }
            }

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
            foreach (var header in original.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            var text = original.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            clone.Content = new StringContent(text, Encoding.UTF8, original.Content.Headers.ContentType?.MediaType ?? "text/html");
            return clone;
        }
    }
}
