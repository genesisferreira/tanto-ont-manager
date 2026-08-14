using System.Net;
using System.Text.RegularExpressions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BScriptReference
{
    private static readonly Regex ScriptSrc = new(
        "(?is)<script[^>]*?src\\s*=\\s*[\"']([^\"']+)[\"']",
        RegexOptions.Compiled);

    public static IReadOnlyList<string> Extract(string? html, IPAddress boundAddress, Uri baseUri, int max)
    {
        if (string.IsNullOrWhiteSpace(html) || max <= 0)
        {
            return [];
        }

        var paths = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in ScriptSrc.Matches(html))
        {
            if (!TryNormalize(match.Groups[1].Value, boundAddress, baseUri, out var path))
            {
                continue;
            }

            if (!seen.Add(path))
            {
                continue;
            }

            paths.Add(path);
            if (paths.Count >= max)
            {
                break;
            }
        }

        return paths;
    }

    public static bool TryNormalize(string? src, IPAddress boundAddress, Uri baseUri, out string relativePath)
    {
        relativePath = string.Empty;
        if (string.IsNullOrWhiteSpace(src))
        {
            return false;
        }

        var trimmed = src.Trim();
        if (trimmed.Contains("..", StringComparison.Ordinal)
            || trimmed.Contains('\\', StringComparison.Ordinal)
            || trimmed.Contains('\n', StringComparison.Ordinal))
        {
            return false;
        }

        if (!Uri.TryCreate(baseUri, trimmed, out var uri))
        {
            return false;
        }

        if (!uri.Host.Equals(boundAddress.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        if (!Regex.IsMatch(uri.AbsolutePath, "^/(?:[A-Za-z0-9_\\-]+/)*[A-Za-z0-9_\\-]+\\.js$", RegexOptions.IgnoreCase))
        {
            return false;
        }

        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(segment => F6201BTagSafety.IsBlocked(Path.GetFileNameWithoutExtension(segment))))
        {
            return false;
        }

        relativePath = uri.AbsolutePath;
        return true;
    }
}
