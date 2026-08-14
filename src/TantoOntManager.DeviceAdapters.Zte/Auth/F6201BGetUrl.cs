namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BGetUrl
{
    public static string Normalize(string pathAndQuery)
    {
        if (string.IsNullOrWhiteSpace(pathAndQuery))
        {
            return "/";
        }

        var trimmed = pathAndQuery.Trim();
        var queryIndex = trimmed.IndexOf('?');
        if (queryIndex < 0)
        {
            return trimmed.ToLowerInvariant();
        }

        var path = trimmed[..queryIndex];
        var query = trimmed[(queryIndex + 1)..];
        var pairs = query.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .Select(parts => new
            {
                Key = Uri.UnescapeDataString(parts[0]).ToLowerInvariant(),
                Value = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : string.Empty
            })
            .OrderBy(part => part.Key, StringComparer.Ordinal)
            .ThenBy(part => part.Value, StringComparer.Ordinal)
            .Select(part => part.Key + "=" + part.Value.ToLowerInvariant());
        return path.ToLowerInvariant() + "?" + string.Join("&", pairs);
    }

    public static string Identity(string pathAndQuery)
    {
        if (string.IsNullOrWhiteSpace(pathAndQuery))
        {
            return "/";
        }

        var trimmed = pathAndQuery.Trim();
        var queryIndex = trimmed.IndexOf('?');
        if (queryIndex < 0)
        {
            return trimmed.ToLowerInvariant();
        }

        var path = trimmed[..queryIndex];
        var query = trimmed[(queryIndex + 1)..];
        var pairs = query.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .Select(parts => new
            {
                Key = Uri.UnescapeDataString(parts[0]),
                Value = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : string.Empty
            })
            .Where(part => !string.Equals(part.Key, "_", StringComparison.Ordinal))
            .OrderBy(part => part.Key, StringComparer.OrdinalIgnoreCase)
            .ThenBy(part => part.Value, StringComparer.OrdinalIgnoreCase)
            .Select(part => part.Key.ToLowerInvariant() + "=" + part.Value.ToLowerInvariant());
        return path.ToLowerInvariant() + "?" + string.Join("&", pairs);
    }
}
