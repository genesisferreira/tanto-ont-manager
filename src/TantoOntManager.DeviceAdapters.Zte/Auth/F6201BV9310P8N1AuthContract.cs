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
    public const string LogoutPathAndQuery = "/?_type=loginData&_tag=logout_entry";
    public const string SessionCookieNamePrefix = "SID_HTTPS_";
    public const string XmlChallengeRoot = "ajax_response_xml_root";
    public const int MaxSafeReadPages = 12;
    public const int MaxTotalBodyBytes = 1_500_000;
    public const int MaxTagLength = 80;

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

    public static readonly IReadOnlyList<string> AllowedGetTypes =
    [
        "menuView",
        "menuData",
        "hiddenData"
    ];

    public static readonly IReadOnlyList<string> AuthControlTags =
    [
        "login_entry",
        "login_token",
        "logout_entry",
        "switchlang_entry",
        "modeswitch_entry"
    ];

    private static readonly string[] DestructiveFragments =
    [
        "apply", "save", "submit", "create", "delete", "remove", "reset", "reboot",
        "upgrade", "upload", "restore", "factory", "firmware", "password", "account",
        "write", "set", "modify", "download", "backup", "wizard", "logout", "logoff",
        "chgpwd", "btn_apply", "btn_delete"
    ];

    public static bool PublicPageMatchesContract(string? html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return false;
        }

        return RequiredPublicMarkers.All(marker => html.Contains(marker, StringComparison.Ordinal));
    }

    public static bool IsAuthControlTag(string? tag)
        => !string.IsNullOrWhiteSpace(tag)
           && AuthControlTags.Contains(tag, StringComparer.OrdinalIgnoreCase);

    public static bool IsDestructiveTag(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag))
        {
            return true;
        }

        var normalized = tag.ToLowerInvariant();
        return DestructiveFragments.Any(fragment => normalized.Contains(fragment, StringComparison.Ordinal));
    }

    public static bool IsValidTag(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag) || tag.Length > MaxTagLength)
        {
            return false;
        }

        return Regex.IsMatch(tag, "^[A-Za-z][A-Za-z0-9_\\-]*$");
    }

    public static bool IsAllowedGetType(string? type)
        => !string.IsNullOrWhiteSpace(type)
           && AllowedGetTypes.Contains(type, StringComparer.OrdinalIgnoreCase);

    public static string BuildGetPath(string type, string tag)
        => $"/?_type={type}&_tag={tag}";

    public static bool IsAllowedGet(Uri uri, IPAddress boundAddress, IReadOnlyCollection<string> discoveredKeys)
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

        if (!IsAllowedGetType(type)
            || !IsValidTag(tag)
            || IsDestructiveTag(tag)
            || IsAuthControlTag(tag)
            || !query.Keys.All(key => key is "_type" or "_tag" or "Menu3Location"))
        {
            return false;
        }

        var key = MakeKey(type!, tag!);
        return discoveredKeys.Any(item => item.Equals(key, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsLoginPost(Uri uri, IPAddress boundAddress)
        => IsTypedLoginDataPost(uri, boundAddress, "login_entry");

    public static bool IsLogoutPost(Uri uri, IPAddress boundAddress)
        => IsTypedLoginDataPost(uri, boundAddress, "logout_entry");

    public static string MakeKey(string type, string tag)
        => $"{type}:{tag}";

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

    public static Dictionary<string, string> ParseQuery(string query)
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

    private static bool IsTypedLoginDataPost(Uri uri, IPAddress boundAddress, string expectedTag)
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
               && string.Equals(tag, expectedTag, StringComparison.OrdinalIgnoreCase);
    }
}
