using System.Text.Json;

namespace TantoOntManager.Domain.Observation;

public static class WriteCapabilityDomParser
{
    public static WriteCapabilityDomSnapshot Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new WriteCapabilityDomSnapshot([], [], false);
        }

        var text = json.Trim();
        if (text.StartsWith('"') && text.EndsWith('"'))
        {
            text = JsonSerializer.Deserialize<string>(text) ?? text;
        }

        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        var menu = new List<string>();
        if (root.TryGetProperty("menu", out var menuNode) && menuNode.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in menuNode.EnumerateArray())
            {
                var label = item.GetString();
                if (!string.IsNullOrWhiteSpace(label) && !WriteBodyInspector.IsSensitiveName(label))
                {
                    menu.Add(label.Trim());
                }
            }
        }

        var footer = root.TryGetProperty("footer", out var footerNode) && footerNode.ValueKind == JsonValueKind.True;
        var controls = new List<ObservedDomControl>();
        if (root.TryGetProperty("controls", out var controlNode) && controlNode.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in controlNode.EnumerateArray())
            {
                controls.Add(ReadControl(item));
            }
        }

        return new WriteCapabilityDomSnapshot(menu, controls, footer);
    }

    private static ObservedDomControl ReadControl(JsonElement item)
    {
        var name = ReadString(item, "name");
        var id = ReadString(item, "id");
        var sensitive = item.TryGetProperty("sensitive", out var sensitiveNode) && sensitiveNode.ValueKind == JsonValueKind.True
                        || WriteBodyInspector.IsSensitiveName(name ?? string.Empty)
                        || WriteBodyInspector.IsSensitiveName(id ?? string.Empty);
        var options = new List<string>();
        if (!sensitive && item.TryGetProperty("options", out var optionNode) && optionNode.ValueKind == JsonValueKind.Array)
        {
            foreach (var option in optionNode.EnumerateArray())
            {
                var value = option.GetString();
                if (!string.IsNullOrWhiteSpace(value) && WriteCapabilityTokenScanner.IsPublicEnumeration(value))
                {
                    options.Add(value.Trim());
                }
            }
        }

        return new ObservedDomControl(
            ReadString(item, "tag") ?? "UNKNOWN",
            sensitive ? null : name,
            sensitive ? null : id,
            ReadString(item, "type") ?? string.Empty,
            item.TryGetProperty("disabled", out var disabled) && disabled.ValueKind == JsonValueKind.True,
            item.TryGetProperty("readOnly", out var readOnly) && readOnly.ValueKind == JsonValueKind.True,
            item.TryGetProperty("hidden", out var hidden) && hidden.ValueKind == JsonValueKind.True,
            options,
            sensitive ? null : ReadString(item, "buttonText"),
            ReadString(item, "handler"),
            sensitive);
    }

    private static string? ReadString(JsonElement item, string name)
        => item.TryGetProperty(name, out var node) && node.ValueKind == JsonValueKind.String
            ? node.GetString()
            : null;
}
