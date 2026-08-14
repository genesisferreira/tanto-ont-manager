using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace TantoOntManager.Domain.Observation;

public static class ResponseStructureInspector
{
    private const int MaxKeys = 80;
    private const int MaxBodyChars = 262144;

    public static ResponseStructure Inspect(string normalizedUrl, string? contentType, string? body)
    {
        var text = body ?? string.Empty;
        if (text.Length > MaxBodyChars)
        {
            text = text[..MaxBodyChars];
        }

        var type = (contentType ?? string.Empty).ToLowerInvariant();
        if (LooksLikeJson(type, text))
        {
            return FromJson(normalizedUrl, text);
        }

        if (LooksLikeXml(type, text))
        {
            return FromXml(normalizedUrl, text);
        }

        if (LooksLikeHtml(type, text))
        {
            return FromHtml(normalizedUrl, text);
        }

        return FromJavaScript(normalizedUrl, text);
    }

    private static ResponseStructure FromJson(string url, string text)
    {
        var keys = new List<string>();
        var types = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var samples = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var records = 0;
        try
        {
            using var document = JsonDocument.Parse(text);
            WalkJson(document.RootElement, keys, types, samples, ref records, 0);
        }
        catch (JsonException)
        {
            return Empty(url, "json-invalido");
        }

        return Finish(url, "json", keys, [], [], records, types, samples);
    }

    private static void WalkJson(
        JsonElement element,
        List<string> keys,
        Dictionary<string, string> types,
        Dictionary<string, string> samples,
        ref int records,
        int depth)
    {
        if (depth > 6 || keys.Count >= MaxKeys)
        {
            return;
        }

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                records++;
                foreach (var property in element.EnumerateObject())
                {
                    if (keys.Count >= MaxKeys)
                    {
                        break;
                    }

                    if (!keys.Contains(property.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        keys.Add(property.Name);
                    }

                    types[property.Name] = property.Value.ValueKind.ToString().ToLowerInvariant();
                    if (property.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
                    {
                        samples[property.Name] = ObservationSanitizer.MaskFieldValue(property.Name, property.Value.ToString());
                    }
                    else
                    {
                        WalkJson(property.Value, keys, types, samples, ref records, depth + 1);
                    }
                }

                break;
            case JsonValueKind.Array:
                records += element.GetArrayLength();
                foreach (var child in element.EnumerateArray().Take(8))
                {
                    WalkJson(child, keys, types, samples, ref records, depth + 1);
                }

                break;
        }
    }

    private static ResponseStructure FromXml(string url, string text)
    {
        try
        {
            var document = XDocument.Parse(text, LoadOptions.None);
            var keys = document.Descendants().Select(node => node.Name.LocalName).Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxKeys).ToList();
            var records = document.Descendants().Count();
            return Finish(url, "xml", keys, [], [], records, new Dictionary<string, string>(), new Dictionary<string, string>());
        }
        catch
        {
            return Empty(url, "xml-invalido");
        }
    }

    private static ResponseStructure FromHtml(string url, string text)
    {
        var ids = Regex.Matches(text, "(?i)\\b(?:id|name)\\s*=\\s*['\"]([^'\"]+)['\"]")
            .Select(match => match.Groups[1].Value)
            .Where(value => !string.IsNullOrWhiteSpace(value) && !ObservationUrl.LooksLikeSecret(value, value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(MaxKeys)
            .ToList();
        var columns = Regex.Matches(text, "(?is)<th[^>]*>(.*?)</th>")
            .Select(match => Regex.Replace(match.Groups[1].Value, "(?is)<[^>]+>", " ").Trim())
            .Where(value => !string.IsNullOrWhiteSpace(value) && value.Length < 48)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(40)
            .ToList();
        var rows = Regex.Matches(text, "(?i)</tr>").Count;
        return Finish(url, "html-fragment", [], ids, columns, rows, new Dictionary<string, string>(), new Dictionary<string, string>());
    }

    private static ResponseStructure FromJavaScript(string url, string text)
    {
        var keys = Regex.Matches(text, "(?i)Transfer_meaning\\(\\s*['\"]([^'\"]+)['\"]")
            .Select(match => match.Groups[1].Value)
            .Concat(Regex.Matches(text, "(?i)\\b([A-Za-z_][A-Za-z0-9_]{2,})\\s*[:=]\\s*['\"][^'\"]{0,64}['\"]")
                .Select(match => match.Groups[1].Value))
            .Where(value => !ObservationUrl.LooksLikeSecret(value, value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(MaxKeys)
            .ToList();
        return Finish(url, "javascript-assignment", keys, keys, [], keys.Count == 0 ? 0 : 1, new Dictionary<string, string>(), new Dictionary<string, string>());
    }

    private static bool LooksLikeJson(string contentType, string text)
    {
        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var trimmed = text.TrimStart();
        return trimmed.StartsWith('{') || trimmed.StartsWith('[');
    }

    private static bool LooksLikeXml(string contentType, string text)
        => contentType.Contains("xml", StringComparison.OrdinalIgnoreCase)
           || text.TrimStart().StartsWith("<?xml", StringComparison.OrdinalIgnoreCase)
           || text.TrimStart().StartsWith("<ajax_response", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeHtml(string contentType, string text)
        => contentType.Contains("html", StringComparison.OrdinalIgnoreCase)
           || text.Contains("<table", StringComparison.OrdinalIgnoreCase)
           || text.Contains("<tr", StringComparison.OrdinalIgnoreCase)
           || text.Contains("<div", StringComparison.OrdinalIgnoreCase);

    private static ResponseStructure Finish(
        string url,
        string format,
        IReadOnlyList<string> keys,
        IReadOnlyList<string> ids,
        IReadOnlyList<string> columns,
        int records,
        IReadOnlyDictionary<string, string> types,
        IReadOnlyDictionary<string, string> samples)
        => new(
            url,
            format,
            keys,
            ids,
            columns,
            records,
            types,
            samples.ToDictionary(pair => pair.Key, pair => ObservationSanitizer.MaskFieldValue(pair.Key, pair.Value), StringComparer.OrdinalIgnoreCase));

    private static ResponseStructure Empty(string url, string format)
        => new(url, format, [], [], [], 0, new Dictionary<string, string>(), new Dictionary<string, string>());
}
