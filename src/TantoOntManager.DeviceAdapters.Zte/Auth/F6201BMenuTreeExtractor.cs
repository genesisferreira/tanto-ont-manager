using System.Text.Json;
using System.Text.RegularExpressions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record F6201BMenuNode(string Id, string Kind, string Path, string? Name);

public static class F6201BMenuTreeExtractor
{
    private static readonly Regex Assignment = new(
        @"menuTreeJSON\s*=(?!=)\s*",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static IReadOnlyList<F6201BMenuNode> Extract(string? html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return [];
        }

        var json = ExtractArrayLiteral(html);
        if (json is null)
        {
            return [];
        }

        if (!F6201BJsObjectLiteral.TryParseArray(json, out var document) || document is null)
        {
            return [];
        }

        try
        {
            var nodes = new List<F6201BMenuNode>();
            Walk(document.RootElement, nodes, parentPath: string.Empty);
            return nodes;
        }
        finally
        {
            document.Dispose();
        }
    }

    public static string? ExtractArrayLiteral(string html)
    {
        foreach (Match match in Assignment.Matches(html))
        {
            var cursor = match.Index + match.Length;
            while (cursor < html.Length && char.IsWhiteSpace(html[cursor]))
            {
                cursor++;
            }

            if (cursor >= html.Length || html[cursor] != '[')
            {
                continue;
            }

            var depth = 0;
            for (var i = cursor; i < html.Length; i++)
            {
                var ch = html[i];
                if (ch == '[')
                {
                    depth++;
                }
                else if (ch == ']')
                {
                    depth--;
                    if (depth == 0)
                    {
                        return html[cursor..(i + 1)];
                    }
                }
            }
        }

        return null;
    }

    private static void Walk(JsonElement element, List<F6201BMenuNode> nodes, string parentPath)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in element.EnumerateArray())
            {
                Walk(child, nodes, parentPath);
            }

            return;
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        string? id = null;
        string? name = null;
        var hasArea = false;
        var hasChildren = false;
        JsonElement children = default;
        foreach (var property in element.EnumerateObject())
        {
            if (property.NameEquals("id") && property.Value.ValueKind == JsonValueKind.String)
            {
                id = property.Value.GetString();
            }
            else if (property.NameEquals("name") && property.Value.ValueKind == JsonValueKind.String)
            {
                name = property.Value.GetString();
            }
            else if (property.NameEquals("area"))
            {
                hasArea = true;
            }
            else if (property.NameEquals("children") && property.Value.ValueKind == JsonValueKind.Array)
            {
                hasChildren = true;
                children = property.Value;
            }
        }

        var label = !string.IsNullOrWhiteSpace(name) ? name : id;
        var path = string.IsNullOrWhiteSpace(parentPath)
            ? label ?? string.Empty
            : parentPath + " → " + label;

        if (!string.IsNullOrWhiteSpace(id))
        {
            var kind = hasArea || !hasChildren ? "page" : "folder";
            nodes.Add(new F6201BMenuNode(id, kind, path, name));
        }

        if (hasChildren)
        {
            Walk(children, nodes, path);
        }
    }
}
