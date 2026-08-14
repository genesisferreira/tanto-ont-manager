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
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        if (body.Contains("showloginPage", StringComparison.Ordinal)
            && !body.Contains("showCommonPage", StringComparison.Ordinal)
            && body.Contains("Frm_Username", StringComparison.Ordinal))
        {
            return true;
        }

        return LooksLikeLoginJson(body);
    }

    public static bool LooksLikeSessionExpired(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        if (body.Contains("This page has expired, please refresh and try again.", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (LooksLikeLoginJson(body))
        {
            return true;
        }

        return body.Contains("Please login", StringComparison.OrdinalIgnoreCase)
               && body.Contains("login_need_refresh", StringComparison.Ordinal)
               && !body.Contains("menuTreeJSON", StringComparison.Ordinal);
    }

    public static bool LooksLikeLoginInsteadOfInternalPage(string? body)
        => LooksLikeSessionExpired(body) || LooksLikeLoginJson(body);

    public static bool LooksLikeLoginJson(string? body)
        => !string.IsNullOrWhiteSpace(body)
           && body.Contains("login_need_refresh", StringComparison.Ordinal)
           && !body.Contains("<html", StringComparison.OrdinalIgnoreCase)
           && !body.Contains("MenuPage", StringComparison.Ordinal);

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
}
