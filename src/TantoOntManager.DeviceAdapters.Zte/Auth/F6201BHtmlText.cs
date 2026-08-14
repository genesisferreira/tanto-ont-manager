using System.Net;
using System.Text.RegularExpressions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BHtmlText
{
    public static string Decode(string? html)
        => string.IsNullOrEmpty(html) ? string.Empty : WebUtility.HtmlDecode(html);

    public static string Normalize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        return Regex.Replace(Decode(text), @"\s+", " ").Trim();
    }

    public static string InnerText(string? html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return string.Empty;
        }

        var withoutScripts = Regex.Replace(html, "(?is)<script[^>]*>.*?</script>", " ");
        var withoutTags = Regex.Replace(withoutScripts, "(?is)<[^>]+>", " ");
        return Normalize(withoutTags);
    }

    public static bool LooksLikeLoginPage(string? body)
        => Classify(body) is Domain.Sessions.AuthenticatedPageKind.PublicLoginPage
            or Domain.Sessions.AuthenticatedPageKind.SessionExpiredEvidence;

    public static bool LooksLikeSessionExpired(string? body)
        => Classify(body) == Domain.Sessions.AuthenticatedPageKind.SessionExpiredEvidence;

    public static bool LooksLikeLoginInsteadOfInternalPage(string? body)
        => Classify(body) is Domain.Sessions.AuthenticatedPageKind.PublicLoginPage
            or Domain.Sessions.AuthenticatedPageKind.SessionExpiredEvidence;

    public static bool LooksLikeLoginJson(string? body)
        => !string.IsNullOrWhiteSpace(body)
           && body.Contains("login_need_refresh", StringComparison.Ordinal)
           && !body.Contains("<html", StringComparison.OrdinalIgnoreCase)
           && !body.Contains("MenuPage", StringComparison.Ordinal);

    public static Domain.Sessions.AuthenticatedPageKind Classify(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return Domain.Sessions.AuthenticatedPageKind.UnexpectedPage;
        }

        if (LooksLikeLoginJson(body) || LooksLikeBareExpiryResponse(body))
        {
            return Domain.Sessions.AuthenticatedPageKind.SessionExpiredEvidence;
        }

        var nowStatus = ReadNowStatus(body);
        if (string.Equals(nowStatus, "showloginPage", StringComparison.Ordinal)
            && HasPublicLoginForm(body))
        {
            return Domain.Sessions.AuthenticatedPageKind.PublicLoginPage;
        }

        if (string.Equals(nowStatus, "showCommonPage", StringComparison.Ordinal))
        {
            return Domain.Sessions.AuthenticatedPageKind.AuthenticatedPage;
        }

        if (HasAuthenticatedShell(body) && !HasPublicLoginForm(body))
        {
            return Domain.Sessions.AuthenticatedPageKind.AuthenticatedPage;
        }

        if (HasPublicLoginForm(body))
        {
            return Domain.Sessions.AuthenticatedPageKind.PublicLoginPage;
        }

        if (HasAuthenticatedShell(body))
        {
            return Domain.Sessions.AuthenticatedPageKind.AuthenticatedPage;
        }

        return Domain.Sessions.AuthenticatedPageKind.UnexpectedPage;
    }

    public static string? ReadNowStatus(string? html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return null;
        }

        var match = Regex.Match(html, "var\\s+NowStatus\\s*=\\s*[\"']([^\"']+)[\"']");
        return match.Success ? DecodeJsString(match.Groups[1].Value) : null;
    }

    public static string SanitizedMarker(string? body)
    {
        var kind = Classify(body);
        var now = ReadNowStatus(body) ?? "none";
        var hasMenu = body?.Contains("menuTreeJSON", StringComparison.Ordinal) == true;
        var hasLogOff = body?.Contains("function LogOff", StringComparison.Ordinal) == true;
        var hasForm = HasPublicLoginForm(body);
        return $"kind={kind}; nowStatus={now}; menuTree={hasMenu}; logOffJs={hasLogOff}; loginForm={hasForm}";
    }

    public static string? ReadSessionToken(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        var tmp = Regex.Match(body, "var\\s+_sessionTmpToken\\s*=\\s*['\"]([^'\"]+)['\"]");
        if (tmp.Success && !string.IsNullOrWhiteSpace(tmp.Groups[1].Value))
        {
            return tmp.Groups[1].Value;
        }

        var json = Regex.Match(body, "\"sess_token\"\\s*:\\s*\"([^\"]+)\"");
        return json.Success ? json.Groups[1].Value : null;
    }

    public static string SnippetAround(string text, string needle, int radius = 48)
    {
        var idx = text.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return Normalize(text.Length <= 96 ? text : text[..96]);
        }

        var start = Math.Max(0, idx - radius);
        var length = Math.Min(text.Length - start, radius * 2 + needle.Length);
        return Normalize(text.Substring(start, length));
    }

    private static bool LooksLikeBareExpiryResponse(string body)
    {
        if (!body.Contains("This page has expired, please refresh and try again.", StringComparison.OrdinalIgnoreCase)
            && !body.Contains("Please login", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (body.Contains("function LogOff", StringComparison.Ordinal)
            || body.Contains("menuTreeJSON", StringComparison.Ordinal)
            || body.Contains("MenuPage=", StringComparison.Ordinal))
        {
            return false;
        }

        return LooksLikeLoginJson(body) || !body.Contains("<html", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasPublicLoginForm(string? body)
        => !string.IsNullOrWhiteSpace(body)
           && body.Contains("Frm_Username", StringComparison.Ordinal)
           && body.Contains("Frm_Password", StringComparison.Ordinal)
           && body.Contains("LoginId", StringComparison.Ordinal);

    private static bool HasAuthenticatedShell(string body)
        => body.Contains("menuTreeJSON", StringComparison.Ordinal)
           && body.Contains("MenuPage=", StringComparison.Ordinal)
           && !string.Equals(ReadNowStatus(body), "showloginPage", StringComparison.Ordinal);

    private static string DecodeJsString(string value)
    {
        return Regex.Replace(
            value,
            @"\\x([0-9A-Fa-f]{2})",
            match => ((char)Convert.ToInt32(match.Groups[1].Value, 16)).ToString());
    }
}
