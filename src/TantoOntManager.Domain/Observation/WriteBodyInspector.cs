using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace TantoOntManager.Domain.Observation;

public static class WriteBodyInspector
{
    private static readonly Regex MultipartName = new(
        "(?i)name\\s*=\\s*\"([^\"]+)\"",
        RegexOptions.Compiled);

    public static IReadOnlyList<ObservedWriteField> Inspect(string? contentType, string? body)
    {
        var fields = new List<ObservedWriteField>();
        if (string.IsNullOrEmpty(body))
        {
            return fields;
        }

        var type = contentType ?? string.Empty;
        if (type.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            CollectJson(body, fields);
        }
        else if (type.Contains("xml", StringComparison.OrdinalIgnoreCase) || body.TrimStart().StartsWith('<'))
        {
            CollectXml(body, fields);
        }
        else if (type.Contains("multipart", StringComparison.OrdinalIgnoreCase))
        {
            CollectMultipart(body, fields);
        }
        else
        {
            CollectForm(body, fields);
        }

        return fields;
    }

    public static ObservedWritePayload ToPayload(
        string? contentType,
        string? body,
        string? referer,
        string? initiator,
        string? actionName)
    {
        string? refererPath = null;
        if (!string.IsNullOrWhiteSpace(referer) && Uri.TryCreate(referer, UriKind.Absolute, out var refererUri))
        {
            refererPath = ObservationUrl.PathSanitized(refererUri);
        }

        return new ObservedWritePayload(
            contentType,
            Inspect(contentType, body),
            refererPath,
            ObservationSanitizer.SanitizeText(initiator),
            actionName);
    }

    public static string LengthBucket(int length)
        => length switch
        {
            0 => "0",
            <= 7 => "1-7",
            <= 16 => "8-16",
            <= 32 => "17-32",
            _ => "33+"
        };

    public static bool IsSensitiveName(string name)
        => ObservationUrl.LooksLikeSecret(name, string.Empty)
           || Regex.IsMatch(name, "(?i)(pass|pwd|senha|token|challenge|sid|cookie|auth|user|pppoe|loid|serial|mac|gponsn)");

    private static void CollectForm(string body, List<ObservedWriteField> fields)
    {
        foreach (var part in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pieces = part.Split('=', 2);
            var name = Uri.UnescapeDataString(pieces[0].Replace('+', ' '));
            var value = pieces.Length > 1 ? Uri.UnescapeDataString(pieces[1].Replace('+', ' ')) : string.Empty;
            fields.Add(Describe(name, value));
        }
    }

    private static void CollectMultipart(string body, List<ObservedWriteField> fields)
    {
        var names = MultipartName.Matches(body);
        foreach (Match match in names)
        {
            fields.Add(Describe(match.Groups[1].Value, DetectMultipartValue(body, match)));
        }
    }

    private static string DetectMultipartValue(string body, Match nameMatch)
    {
        var start = nameMatch.Index + nameMatch.Length;
        var end = body.IndexOf("\r\n--", start, StringComparison.Ordinal);
        if (end < 0)
        {
            end = Math.Min(body.Length, start + 256);
        }

        var slice = body[start..end];
        var blank = slice.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return blank >= 0 ? slice[(blank + 4)..].Trim() : string.Empty;
    }

    private static void CollectJson(string body, List<ObservedWriteField> fields)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            CollectJsonElement(document.RootElement, fields);
        }
        catch (JsonException)
        {
            CollectForm(body, fields);
        }
    }

    private static void CollectJsonElement(JsonElement element, List<ObservedWriteField> fields)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                {
                    CollectJsonElement(property.Value, fields);
                    continue;
                }

                fields.Add(Describe(property.Name, property.Value.ToString()));
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in element.EnumerateArray())
            {
                CollectJsonElement(child, fields);
            }
        }
    }

    private static void CollectXml(string body, List<ObservedWriteField> fields)
    {
        try
        {
            var document = XDocument.Parse(body, LoadOptions.None);
            foreach (var name in document.Descendants().Where(node =>
                         node.Name.LocalName.Equals("ParaName", StringComparison.OrdinalIgnoreCase)))
            {
                var value = name.ElementsAfterSelf()
                    .FirstOrDefault(node => node.Name.LocalName.Equals("ParaValue", StringComparison.OrdinalIgnoreCase))
                    ?.Value ?? string.Empty;
                fields.Add(Describe(name.Value.Trim(), value));
            }

            if (fields.Count == 0)
            {
                foreach (var element in document.Descendants().Where(node => !node.HasElements))
                {
                    fields.Add(Describe(element.Name.LocalName, element.Value));
                }
            }
        }
        catch
        {
            CollectForm(body, fields);
        }
    }

    private static ObservedWriteField Describe(string name, string? rawValue)
    {
        var value = rawValue ?? string.Empty;
        var sensitive = IsSensitiveName(name);
        var present = value.Length > 0;
        var type = ClassifyType(name, value);
        var shown = sensitive
            ? "[redacted]"
            : (CanRecordPublicValue(name, value, type) ? value : (present ? "[redacted]" : string.Empty));
        return new ObservedWriteField(
            name,
            sensitive,
            present,
            LengthBucket(value.Length),
            type,
            shown);
    }

    private static string ClassifyType(string name, string value)
    {
        if (IsSensitiveName(name))
        {
            return "secret";
        }

        if (string.IsNullOrEmpty(value))
        {
            return "empty";
        }

        if (value is "0" or "1" or "true" or "false" or "on" or "off"
            or "On" or "Off" or "enable" or "disable" or "Enable" or "Disable")
        {
            return "boolean";
        }

        if (int.TryParse(value, out _))
        {
            return "integer";
        }

        if (Regex.IsMatch(name, "(?i)(type|mode|list|version|status)"))
        {
            return "enumeration";
        }

        return "text";
    }

    private static bool CanRecordPublicValue(string name, string value, string type)
    {
        if (IsSensitiveName(name) || value.Length > 24)
        {
            return false;
        }

        if (type is "boolean" or "integer" or "enumeration")
        {
            return true;
        }

        return Regex.IsMatch(name, "(?i)(vlan|mtu|priority|802)");
    }
}
