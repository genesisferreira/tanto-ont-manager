using System.Net;
using System.Text.RegularExpressions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BV9310P8N1AuthContract
{
    public const string AdapterId = "zte-f6201b-v9.3.10p8n1-auth-v1";
    public const string AuthenticationMethod = "zte-f6201b-v9.3.10p8n1-json-login";
    public const string ExpectedSoftware = "V9.3.10P8N1";
    public const string ExpectedHardware = "V9.3.12";
    public const string LoginPathAndQuery = "/?_type=loginData&_tag=login_entry";
    public const string TokenPathAndQuery = "/?_type=loginData&_tag=login_token";
    public const string SessionCookieNamePrefix = "SID_HTTPS_";
    public const string XmlChallengeRoot = "ajax_response_xml_root";

    public static readonly IReadOnlyList<string> RequiredPublicMarkers =
    [
        "Frm_Username",
        "Frm_Password",
        "_sessionTOKEN",
        "loginData&_tag=login_entry",
        "loginData&_tag=login_token",
        "login_need_refresh",
        "g_loginToken"
    ];

    private static readonly string[] DestructiveFragments =
    [
        "reboot", "reset", "factory", "firmware", "upgrade", "restore", "upload",
        "download", "backup", "save", "apply", "delete", "create", "wizard",
        "logout", "logoff", "chgpwd", "password", "accountmgr", "btn_apply",
        "btn_delete"
    ];

    private static readonly Regex MenuPage = new(
        "MenuPage\\s*=\\s*['\"]([A-Za-z0-9_\\-]+)['\"]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex TagQuery = new(
        "_tag=([A-Za-z0-9_\\-]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex OpenLink = new(
        "openLink\\(\\s*['\"]([A-Za-z0-9_\\-]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool PublicPageMatchesContract(string? html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return false;
        }

        return RequiredPublicMarkers.All(marker => html.Contains(marker, StringComparison.Ordinal));
    }

    public static bool IsDestructiveTag(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag))
        {
            return true;
        }

        var normalized = tag.ToLowerInvariant();
        return DestructiveFragments.Any(fragment => normalized.Contains(fragment, StringComparison.Ordinal));
    }

    public static IReadOnlyList<string> DiscoverMenuTags(string? html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return [];
        }

        var tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in MenuPage.Matches(html))
        {
            tags.Add(match.Groups[1].Value);
        }

        foreach (Match match in OpenLink.Matches(html))
        {
            tags.Add(match.Groups[1].Value);
        }

        foreach (Match match in TagQuery.Matches(html))
        {
            var tag = match.Groups[1].Value;
            if (tag is "login_entry" or "login_token" or "logout_entry" or "switchlang_entry" or "modeswitch_entry")
            {
                continue;
            }

            tags.Add(tag);
        }

        return tags.ToList();
    }

    public static bool IsAllowedGet(Uri uri, IPAddress boundAddress, IReadOnlyCollection<string> discoveredTags)
    {
        if (uri.Scheme is not ("http" or "https"))
        {
            return false;
        }

        if (!uri.Host.Equals(boundAddress.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (uri.AbsolutePath is not "/")
        {
            return false;
        }

        var query = ParseQuery(uri.Query);
        if (query.Count == 0)
        {
            return true;
        }

        query.TryGetValue("_type", out var type);
        query.TryGetValue("_tag", out var tag);

        if (string.Equals(type, "loginData", StringComparison.OrdinalIgnoreCase)
            && tag is "login_entry" or "login_token"
            && query.Count == 2)
        {
            return true;
        }

        if (string.Equals(type, "menuView", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(tag)
            && !IsDestructiveTag(tag)
            && discoveredTags.Any(item => item.Equals(tag, StringComparison.OrdinalIgnoreCase))
            && query.Keys.All(key => key is "_type" or "_tag" or "Menu3Location"))
        {
            return true;
        }

        return false;
    }

    public static bool IsLoginPost(Uri uri, IPAddress boundAddress)
    {
        if (!uri.Host.Equals(boundAddress.ToString(), StringComparison.OrdinalIgnoreCase)
            || uri.AbsolutePath is not "/")
        {
            return false;
        }

        var query = ParseQuery(uri.Query);
        return query.Count == 2
               && query.TryGetValue("_type", out var type)
               && query.TryGetValue("_tag", out var tag)
               && string.Equals(type, "loginData", StringComparison.OrdinalIgnoreCase)
               && string.Equals(tag, "login_entry", StringComparison.OrdinalIgnoreCase);
    }

    public static string MaskUri(Uri uri)
    {
        var query = ParseQuery(uri.Query);
        if (query.Count == 0)
        {
            return uri.AbsolutePath;
        }

        var safe = query.Select(pair =>
        {
            if (pair.Key is "_type" or "_tag" or "Menu3Location")
            {
                return $"{pair.Key}={pair.Value}";
            }

            return $"{pair.Key}=[redacted]";
        });

        return uri.AbsolutePath + "?" + string.Join('&', safe);
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
        {
            return result;
        }

        var trimmed = query.TrimStart('?');
        foreach (var part in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = part.IndexOf('=');
            if (idx <= 0)
            {
                continue;
            }

            result[Uri.UnescapeDataString(part[..idx])] = Uri.UnescapeDataString(part[(idx + 1)..]);
        }

        return result;
    }
}
