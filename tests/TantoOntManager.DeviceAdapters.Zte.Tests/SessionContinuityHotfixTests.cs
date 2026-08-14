using FluentAssertions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class SessionContinuityHotfixTests
{
    [Fact]
    public void RealOnt_Regression_AuthenticatedHomeWithLogOffScript_IsNotSessionExpired()
    {
        var home = """
            <html><head><title>F6201B</title></head><body>
            <script>
            var NowStatus = "showCommonPage";
            var menuTreeJSON = [{"id":"homePage","name":"Home","area":[{"area":"home_t.lp"}]}];
            function LogOff() {
              $.post("/?_type=loginData&_tag=logout_entry", {IF_LogOff:1, _sessionTOKEN:_sessionTmpToken})
               .done(function(data){ alert("This page has expired, please refresh and try again. "); });
            }
            var _sessionTmpToken = "tok-session";
            </script>
            <p MenuPage="devinfo">Device Information</p>
            <div id="commPageContainer"></div>
            </body></html>
            """;

        F6201BHtmlText.LooksLikeSessionExpired(home).Should().BeFalse();
        F6201BHtmlText.Classify(home).Should().Be(AuthenticatedPageKind.AuthenticatedPage);
        F6201BHtmlText.ReadNowStatus(home).Should().Be("showCommonPage");
    }

    [Fact]
    public void Empty_or_duplicate_or_partial_html_is_not_session_expired()
    {
        F6201BHtmlText.LooksLikeSessionExpired("").Should().BeFalse();
        F6201BHtmlText.LooksLikeSessionExpired("<html><body>Dashboard</body></html>").Should().BeFalse();
        F6201BHtmlText.Classify("<html><body></body></html>").Should().Be(AuthenticatedPageKind.UnexpectedPage);
        var parsed = F6201BV9310P8N1DeviceInformationParser.Parse(("/", "<html><body></body></html>"));
        parsed.SoftwareVersion.Should().BeNull();
    }

    [Fact]
    public void Public_login_form_and_login_json_are_strong_expiry_or_login_page()
    {
        var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-v9310p8n1-session-expired.json"));
        F6201BHtmlText.Classify(json).Should().Be(AuthenticatedPageKind.SessionExpiredEvidence);
        var login = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-v9310p8n1-login-contract.html"));
        F6201BHtmlText.Classify(login).Should().Be(AuthenticatedPageKind.PublicLoginPage);
    }

    [Fact]
    public void Hex_encoded_nowstatus_showloginPage_is_public_login()
    {
        var html = "<html><body><script>var NowStatus = \"\\x73\\x68\\x6f\\x77\\x6c\\x6f\\x67\\x69\\x6e\\x50\\x61\\x67\\x65\";</script>"
                   + "<input id=\"Frm_Username\"/><input id=\"Frm_Password\"/><button id=\"LoginId\"></button></body></html>";
        F6201BHtmlText.ReadNowStatus(html).Should().Be("showloginPage");
        F6201BHtmlText.Classify(html).Should().Be(AuthenticatedPageKind.PublicLoginPage);
    }

    [Fact]
    public void Complete_public_login_form_is_not_an_authenticated_page()
    {
        var login = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "zte-f6201b-v9310p8n1-login-contract.html"));
        F6201BHtmlText.LooksLikeLoginInsteadOfInternalPage(login).Should().BeTrue();
        F6201BHtmlText.Classify(login).Should().Be(AuthenticatedPageKind.PublicLoginPage);
    }

    [Fact]
    public void Redirect_target_login_json_is_session_expired_evidence()
    {
        var json = """{"login_need_refresh":true,"loginErrMsg":"Please login","promptMsg":""}""";
        F6201BHtmlText.Classify(json).Should().Be(AuthenticatedPageKind.SessionExpiredEvidence);
        F6201BHtmlText.LooksLikeSessionExpired(json).Should().BeTrue();
    }
}
