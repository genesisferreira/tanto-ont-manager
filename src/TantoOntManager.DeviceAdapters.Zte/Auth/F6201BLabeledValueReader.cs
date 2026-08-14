using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record ParsedField(string? Value, FieldEvidence? Evidence)
{
    public static ParsedField Missing { get; } = new(null, null);

    public bool Found => !string.IsNullOrWhiteSpace(Value);
}

public static class F6201BLabeledValueReader
{
    private static readonly Regex TransferMeaning = new(
        "Transfer_meaning\\(\\s*['\"]([^'\"]+)['\"]\\s*,\\s*['\"]([^'\"]*)['\"]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IdValue = new(
        "<[^>]+(?:id|name)\\s*=\\s*['\"](?<id>[^'\"]+)['\"][^>]*>(?<inner>[^<]*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex InputValue = new(
        "<input[^>]+(?:id|name)\\s*=\\s*['\"](?<id>[^'\"]+)['\"][^>]*value\\s*=\\s*['\"](?<value>[^'\"]*)['\"]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly HashSet<string> SecretKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "ppppassword", "wanpassword", "keypassphrase", "wpakey", "wlanpassword"
    };

    private static readonly HashSet<string> PasswordKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "ppppassword", "wanpassword", "keypassphrase", "wpakey", "wlanpassword", "ppppwd"
    };

    public static ParsedField Read(string pageName, string html, params string[] labelsAndKeys)
    {
        if (string.IsNullOrWhiteSpace(html) || labelsAndKeys.Length == 0)
        {
            return ParsedField.Missing;
        }

        var decoded = F6201BHtmlText.Decode(html);
        return ReadJson(pageName, decoded, labelsAndKeys)
               ?? ReadTransferMeaning(pageName, decoded, labelsAndKeys)
               ?? ReadTablePairs(pageName, decoded, labelsAndKeys)
               ?? ReadNamedNodes(pageName, decoded, labelsAndKeys)
               ?? ReadNormalizedLabel(pageName, decoded, labelsAndKeys)
               ?? ParsedField.Missing;
    }

    public static ParsedField ReadExact(string pageName, string html, params string[] labelsAndKeys)
    {
        if (string.IsNullOrWhiteSpace(html) || labelsAndKeys.Length == 0)
        {
            return ParsedField.Missing;
        }

        var decoded = F6201BHtmlText.Decode(html);
        return ReadXmlParaExact(pageName, decoded, labelsAndKeys)
               ?? ReadJsonExact(pageName, decoded, labelsAndKeys)
               ?? ReadTransferMeaningExact(pageName, decoded, labelsAndKeys)
               ?? ReadTablePairsExact(pageName, decoded, labelsAndKeys)
               ?? ReadNamedNodesExact(pageName, decoded, labelsAndKeys)
               ?? ReadExactColonLabel(pageName, decoded, labelsAndKeys)
               ?? ParsedField.Missing;
    }

    public static IReadOnlyList<IReadOnlyDictionary<string, string>> ReadJsonObjectArrays(string html)
    {
        var result = new List<IReadOnlyDictionary<string, string>>();
        if (string.IsNullOrWhiteSpace(html))
        {
            return result;
        }

        var decoded = F6201BHtmlText.Decode(html).Trim();
        if (!LooksLikeJson(decoded))
        {
            var match = Regex.Match(decoded, "\\{[\\s\\S]*\\}");
            if (!match.Success)
            {
                return result;
            }

            decoded = match.Value;
        }

        try
        {
            using var document = JsonDocument.Parse(decoded);
            CollectObjects(document.RootElement, result);
        }
        catch (JsonException)
        {
            return result;
        }

        return result;
    }

    public static bool IsSecretKey(string key)
        => SecretKeys.Any(secret => key.Contains(secret, StringComparison.OrdinalIgnoreCase));

    public static bool IsPasswordKey(string key)
        => PasswordKeys.Any(secret => key.Contains(secret, StringComparison.OrdinalIgnoreCase));

    public static IReadOnlyList<IReadOnlyDictionary<string, string>> ReadXmlInstances(string xml)
    {
        var result = new List<IReadOnlyDictionary<string, string>>();
        if (string.IsNullOrWhiteSpace(xml) || xml.IndexOf("ParaName", StringComparison.OrdinalIgnoreCase) < 0)
        {
            return result;
        }

        var decoded = F6201BHtmlText.Decode(xml);
        foreach (Match instance in Regex.Matches(decoded, "(?is)<Instance>(.*?)</Instance>"))
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match pair in Regex.Matches(
                         instance.Groups[1].Value,
                         "(?is)<ParaName>\\s*([^<]+?)\\s*</ParaName>\\s*<ParaValue>\\s*([^<]*?)\\s*</ParaValue>"))
            {
                var name = F6201BHtmlText.Normalize(pair.Groups[1].Value);
                var value = F6201BHtmlText.Normalize(pair.Groups[2].Value);
                if (string.IsNullOrWhiteSpace(name) || IsPasswordKey(name))
                {
                    continue;
                }

                map[name] = value;
            }

            if (map.Count > 0)
            {
                result.Add(map);
            }
        }

        return result;
    }

    private static ParsedField? ReadXmlParaExact(string pageName, string xml, string[] labelsAndKeys)
    {
        foreach (var obj in ReadXmlInstances(xml))
        {
            foreach (var key in labelsAndKeys)
            {
                foreach (var pair in obj)
                {
                    if (F6201BFieldAssociation.NamesEqual(pair.Key, key)
                        && !IsPasswordKey(pair.Key)
                        && F6201BFieldAssociation.IsUsableScalar(pair.Value))
                    {
                        return F6201BFieldAssociation.Evidence(key, pair.Value, pageName, "xml-paraname", pair.Key, null);
                    }
                }
            }
        }

        return null;
    }

    private static ParsedField? ReadJson(string pageName, string html, string[] labelsAndKeys)
    {
        foreach (var obj in ReadJsonObjectArrays(html))
        {
            foreach (var key in labelsAndKeys)
            {
                foreach (var pair in obj)
                {
                    if (NamesMatch(pair.Key, key) && !IsSecretKey(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value))
                    {
                        return new ParsedField(
                            pair.Value.Trim(),
                            new FieldEvidence(key, pair.Value.Trim(), pageName, "json-property", pair.Key + "=" + pair.Value.Trim()));
                    }
                }
            }
        }

        return null;
    }

    private static ParsedField? ReadTransferMeaning(string pageName, string html, string[] labelsAndKeys)
    {
        foreach (Match match in TransferMeaning.Matches(html))
        {
            var key = match.Groups[1].Value;
            var value = match.Groups[2].Value.Trim();
            if (string.IsNullOrWhiteSpace(value) || IsSecretKey(key))
            {
                continue;
            }

            if (labelsAndKeys.Any(label => NamesMatch(key, label)))
            {
                return new ParsedField(
                    value,
                    new FieldEvidence(key, value, pageName, "transfer-meaning", match.Value));
            }
        }

        return null;
    }

    private static ParsedField? ReadTablePairs(string pageName, string html, string[] labelsAndKeys)
    {
        var rows = Regex.Split(html, "(?i)</tr>");
        foreach (var row in rows)
        {
            var cells = Regex.Matches(row, "(?is)<t[dh][^>]*>(.*?)</t[dh]>")
                .Select(match => F6201BHtmlText.Normalize(Regex.Replace(match.Groups[1].Value, "(?is)<[^>]+>", " ")))
                .Where(text => !string.IsNullOrWhiteSpace(text))
                .ToList();
            if (cells.Count < 2)
            {
                continue;
            }

            var label = cells[0];
            var value = cells[1];
            if (labelsAndKeys.Any(candidate => NamesMatch(label, candidate)) && !LooksLikeSecretLabel(label))
            {
                return new ParsedField(
                    value,
                    new FieldEvidence(label, value, pageName, "html-table", label + " = " + value));
            }
        }

        return null;
    }

    private static ParsedField? ReadNamedNodes(string pageName, string html, string[] labelsAndKeys)
    {
        foreach (Match match in InputValue.Matches(html))
        {
            var id = match.Groups["id"].Value;
            var value = F6201BHtmlText.Normalize(match.Groups["value"].Value);
            if (string.IsNullOrWhiteSpace(value) || IsSecretKey(id))
            {
                continue;
            }

            if (labelsAndKeys.Any(label => NamesMatch(id, label)))
            {
                return new ParsedField(value, new FieldEvidence(id, value, pageName, "input-value", id));
            }
        }

        foreach (Match match in IdValue.Matches(html))
        {
            var id = match.Groups["id"].Value;
            var value = F6201BHtmlText.Normalize(match.Groups["inner"].Value);
            if (string.IsNullOrWhiteSpace(value) || IsSecretKey(id))
            {
                continue;
            }

            if (labelsAndKeys.Any(label => NamesMatch(id, label)))
            {
                return new ParsedField(value, new FieldEvidence(id, value, pageName, "element-id", id + "=" + value));
            }
        }

        return null;
    }

    private static ParsedField? ReadNormalizedLabel(string pageName, string html, string[] labelsAndKeys)
    {
        var text = F6201BHtmlText.InnerText(html);
        foreach (var label in labelsAndKeys)
        {
            var pattern = $@"(?i){Regex.Escape(label)}\s*[:：=]\s*(.+?)(?=\s+(?:Hardware|Software|Boot|Serial|MAC|ONU|Temperature|VLAN|Status|Device|Optical|Supply|Transmitter|Type|Name)\b|$)";
            var match = Regex.Match(text, pattern);
            if (match.Success)
            {
                var value = match.Groups[1].Value.Trim();
                if (!string.IsNullOrWhiteSpace(value) && !LooksLikeSecretLabel(label))
                {
                    return new ParsedField(
                        value,
                        new FieldEvidence(label, value, pageName, "normalized-label", F6201BHtmlText.SnippetAround(text, label)));
                }
            }
        }

        return null;
    }

    private static ParsedField? ReadJsonExact(string pageName, string html, string[] labelsAndKeys)
    {
        foreach (var obj in ReadJsonObjectArrays(html))
        {
            foreach (var key in labelsAndKeys)
            {
                foreach (var pair in obj)
                {
                    if (F6201BFieldAssociation.NamesEqual(pair.Key, key)
                        && !IsSecretKey(pair.Key)
                        && F6201BFieldAssociation.IsUsableScalar(pair.Value))
                    {
                        return F6201BFieldAssociation.Evidence(key, pair.Value, pageName, "json-property", pair.Key, null);
                    }
                }
            }
        }

        return null;
    }

    private static ParsedField? ReadTransferMeaningExact(string pageName, string html, string[] labelsAndKeys)
    {
        foreach (Match match in TransferMeaning.Matches(html))
        {
            var key = match.Groups[1].Value;
            var value = match.Groups[2].Value.Trim();
            if (!F6201BFieldAssociation.IsUsableScalar(value) || IsSecretKey(key))
            {
                continue;
            }

            if (labelsAndKeys.Any(label => F6201BFieldAssociation.NamesEqual(key, label)))
            {
                return F6201BFieldAssociation.Evidence(key, value, pageName, "transfer-meaning", key, null);
            }
        }

        return null;
    }

    private static ParsedField? ReadTablePairsExact(string pageName, string html, string[] labelsAndKeys)
    {
        var rows = Regex.Split(html, "(?i)</tr>");
        foreach (var row in rows)
        {
            var cells = Regex.Matches(row, "(?is)<t[dh][^>]*>(.*?)</t[dh]>")
                .Select(match => F6201BHtmlText.Normalize(Regex.Replace(match.Groups[1].Value, "(?is)<[^>]+>", " ")))
                .Where(text => !string.IsNullOrWhiteSpace(text))
                .ToList();
            if (cells.Count < 2)
            {
                continue;
            }

            var label = cells[0];
            var value = cells[1];
            if (labelsAndKeys.Any(candidate => F6201BFieldAssociation.NamesEqual(label, candidate))
                && !LooksLikeSecretLabel(label)
                && F6201BFieldAssociation.IsUsableScalar(value))
            {
                return F6201BFieldAssociation.Evidence(label, value, pageName, "html-table", label, null);
            }
        }

        return null;
    }

    private static ParsedField? ReadNamedNodesExact(string pageName, string html, string[] labelsAndKeys)
    {
        foreach (Match match in InputValue.Matches(html))
        {
            var id = match.Groups["id"].Value;
            var value = F6201BHtmlText.Normalize(match.Groups["value"].Value);
            if (!F6201BFieldAssociation.IsUsableScalar(value) || IsSecretKey(id))
            {
                continue;
            }

            if (labelsAndKeys.Any(label => F6201BFieldAssociation.NamesEqual(id, label)))
            {
                return F6201BFieldAssociation.Evidence(id, value, pageName, "input-value", id, null);
            }
        }

        foreach (Match match in IdValue.Matches(html))
        {
            var id = match.Groups["id"].Value;
            var value = F6201BHtmlText.Normalize(match.Groups["inner"].Value);
            if (!F6201BFieldAssociation.IsUsableScalar(value) || IsSecretKey(id))
            {
                continue;
            }

            if (labelsAndKeys.Any(label => F6201BFieldAssociation.NamesEqual(id, label)))
            {
                return F6201BFieldAssociation.Evidence(id, value, pageName, "element-id", id, null);
            }
        }

        return null;
    }

    private static ParsedField? ReadExactColonLabel(string pageName, string html, string[] labelsAndKeys)
    {
        var text = F6201BHtmlText.InnerText(html);
        foreach (var label in labelsAndKeys)
        {
            var pattern = $@"(?i)(?<![A-Za-z0-9]){Regex.Escape(label)}\s*[:：=]\s*(.+?)(?=\s+(?:Hardware|Software|Boot|Serial|MAC|ONU|Device|Temperature)\b|$)";
            var match = Regex.Match(text, pattern);
            if (!match.Success)
            {
                continue;
            }

            var value = F6201BHtmlText.Normalize(match.Groups[1].Value);
            if (F6201BFieldAssociation.IsUsableScalar(value) && !LooksLikeSecretLabel(label))
            {
                return F6201BFieldAssociation.Evidence(label, value, pageName, "exact-label", label, null);
            }
        }

        return null;
    }

    private static void CollectObjects(JsonElement element, List<IReadOnlyDictionary<string, string>> sink)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
                    {
                        var text = property.Value.ToString();
                        if (!string.IsNullOrWhiteSpace(text) && !IsSecretKey(property.Name))
                        {
                            map[property.Name] = text;
                        }
                    }
                    else
                    {
                        CollectObjects(property.Value, sink);
                    }
                }

                if (map.Count > 0)
                {
                    sink.Add(map);
                }

                break;
            case JsonValueKind.Array:
                foreach (var child in element.EnumerateArray())
                {
                    CollectObjects(child, sink);
                }

                break;
        }
    }

    private static bool LooksLikeJson(string text)
    {
        var trimmed = text.TrimStart();
        return trimmed.StartsWith('{') || trimmed.StartsWith('[');
    }

    private static bool LooksLikeSecretLabel(string label)
        => IsSecretKey(label.Replace(" ", string.Empty));

    private static bool NamesMatch(string actual, string expected)
    {
        var left = NormalizeName(actual);
        var right = NormalizeName(expected);
        return left.Equals(right, StringComparison.OrdinalIgnoreCase)
               || left.Contains(right, StringComparison.OrdinalIgnoreCase)
               || right.Contains(left, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeName(string value)
        => Regex.Replace(value, "[^A-Za-z0-9]", string.Empty);

    public static int? ParseInt(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var digits = Regex.Match(value, "-?\\d+");
        return digits.Success && int.TryParse(digits.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number)
            ? number
            : null;
    }

    public static bool? ParseBool(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (value.Equals("1", StringComparison.Ordinal) || value.Equals("true", StringComparison.OrdinalIgnoreCase)
            || value.Equals("enable", StringComparison.OrdinalIgnoreCase) || value.Equals("enabled", StringComparison.OrdinalIgnoreCase)
            || value.Equals("on", StringComparison.OrdinalIgnoreCase) || value.Equals("yes", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (value.Equals("0", StringComparison.Ordinal) || value.Equals("false", StringComparison.OrdinalIgnoreCase)
            || value.Equals("disable", StringComparison.OrdinalIgnoreCase) || value.Equals("disabled", StringComparison.OrdinalIgnoreCase)
            || value.Equals("off", StringComparison.OrdinalIgnoreCase) || value.Equals("no", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return null;
    }
}
