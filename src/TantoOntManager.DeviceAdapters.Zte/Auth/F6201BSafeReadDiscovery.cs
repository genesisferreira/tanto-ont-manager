using System.Text.Json;
using System.Text.RegularExpressions;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BSafeReadDiscovery
{
    private static readonly Regex MenuPage = new(
        "MenuPage\\s*=\\s*['\"]([A-Za-z0-9_\\-]+)['\"]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex OpenLink = new(
        "openLink\\(\\s*['\"]([A-Za-z0-9_\\-]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex TypedTag = new(
        "_type=(menuView|menuData|hiddenData)&_tag=([A-Za-z0-9_\\-]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex TagThenType = new(
        "_tag=([A-Za-z0-9_\\-]+)&_type=(menuView|menuData|hiddenData)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ExtraQuery = new(
        "_type=(?:menuView|menuData|hiddenData)&_tag=[A-Za-z0-9_\\-]+&(?!Menu3Location=)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static IReadOnlyList<SafeReadInventoryItem> Discover(string? html, string evidencePage = "/")
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return [];
        }

        var items = new List<SafeReadInventoryItem>();
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string type, string tag, string source, string? menuText = null, bool folder = false)
        {
            var classified = Classify(type, tag, source, html, menuText, folder);
            var key = F6201BV9310P8N1AuthContract.MakeKey(classified.Type, classified.Tag);
            if (!seenKeys.Add(key))
            {
                if (classified.Classification == SafeReadClassification.SafeRead)
                {
                    items.Add(classified.Item with
                    {
                        Classification = SafeReadClassification.Duplicate,
                        ClassificationReason = "Tag já inventariada nesta página.",
                        WasAccessed = false
                    });
                }

                return;
            }

            items.Add(classified.Item);
        }

        var menuByTag = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in ExtractMenuNodes(html))
        {
            if (!string.IsNullOrWhiteSpace(node.Path))
            {
                menuByTag[node.Id] = node.Path;
            }

            Add("menuView", node.Id, $"menuTreeJSON:{node.Kind}@{evidencePage}", node.Path, folder: node.Kind == "folder");
        }

        foreach (Match match in MenuPage.Matches(html))
        {
            var tag = match.Groups[1].Value;
            menuByTag.TryGetValue(tag, out var path);
            Add("menuView", tag, $"MenuPage@{evidencePage}", path);
        }

        foreach (Match match in OpenLink.Matches(html))
        {
            var tag = match.Groups[1].Value;
            menuByTag.TryGetValue(tag, out var path);
            Add("menuView", tag, $"openLink@{evidencePage}", path);
        }

        foreach (Match match in TypedTag.Matches(html))
        {
            var tag = match.Groups[2].Value;
            menuByTag.TryGetValue(tag, out var path);
            Add(match.Groups[1].Value, tag, $"_type+_tag@{evidencePage}", path);
        }

        foreach (Match match in TagThenType.Matches(html))
        {
            var tag = match.Groups[1].Value;
            menuByTag.TryGetValue(tag, out var path);
            Add(match.Groups[2].Value, tag, $"_tag+_type@{evidencePage}", path);
        }

        return Prioritize(items);
    }

    public static IReadOnlyList<SafeReadInventoryItem> Merge(
        IEnumerable<SafeReadInventoryItem> existing,
        IEnumerable<SafeReadInventoryItem> incoming)
    {
        var result = new List<SafeReadInventoryItem>();
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in existing.Concat(incoming))
        {
            var key = item.TypeAndTag;
            if (!keys.Add(key))
            {
                if (item.WasAccessed)
                {
                    var idx = result.FindIndex(candidate => candidate.TypeAndTag.Equals(key, StringComparison.OrdinalIgnoreCase));
                    if (idx >= 0)
                    {
                        result[idx] = item;
                    }
                }

                continue;
            }

            result.Add(item);
        }

        return Prioritize(result);
    }

    private static IReadOnlyList<SafeReadInventoryItem> Prioritize(IReadOnlyList<SafeReadInventoryItem> items)
    {
        return items
            .Select((item, index) => (item, index, rank: Rank(item)))
            .OrderBy(tuple => tuple.rank)
            .ThenBy(tuple => tuple.index)
            .Select(tuple => tuple.item)
            .ToList();
    }

    private static int Rank(SafeReadInventoryItem item)
    {
        if (item.Classification != SafeReadClassification.SafeRead)
        {
            return 80;
        }

        if (item.EvidenceSource.Contains("menuTreeJSON:page", StringComparison.OrdinalIgnoreCase)
            || item.Tag.Equals("homePage", StringComparison.OrdinalIgnoreCase)
            || F6201BPriorityMenu.Match(item.MenuText) is not null)
        {
            return 0;
        }

        if (item.EvidenceSource.Contains("MenuPage", StringComparison.OrdinalIgnoreCase))
        {
            return 1;
        }

        if (item.EvidenceSource.Contains("_type+_tag", StringComparison.OrdinalIgnoreCase)
            || item.EvidenceSource.Contains("_tag+_type", StringComparison.OrdinalIgnoreCase))
        {
            return 2;
        }

        if (item.EvidenceSource.Contains("openLink", StringComparison.OrdinalIgnoreCase))
        {
            return 3;
        }

        return 4;
    }

    private static (string Type, string Tag, SafeReadInventoryItem Item, SafeReadClassification Classification) Classify(
        string type,
        string tag,
        string source,
        string html,
        string? menuText,
        bool folder)
    {
        var normalizedType = string.IsNullOrWhiteSpace(type) ? "menuView" : type;
        var itemBase = new SafeReadInventoryItem(
            tag,
            source,
            "GET",
            null,
            0,
            string.Empty,
            SafeReadClassification.Invalid,
            "Tag ainda não classificada.",
            false)
        {
            TypeAndTag = F6201BV9310P8N1AuthContract.MakeKey(normalizedType, tag),
            MenuText = menuText
        };

        if (!F6201BV9310P8N1AuthContract.IsValidTag(tag)
            || !F6201BV9310P8N1AuthContract.IsAllowedGetType(normalizedType))
        {
            var invalid = itemBase with
            {
                Classification = SafeReadClassification.Invalid,
                ClassificationReason = "Tag ou tipo GET inválido."
            };
            return (normalizedType, tag, invalid, SafeReadClassification.Invalid);
        }

        if (F6201BV9310P8N1AuthContract.IsAuthControlTag(tag))
        {
            var skipped = itemBase with
            {
                Classification = SafeReadClassification.Invalid,
                ClassificationReason = "Tag de controle de autenticação; não é leitura de dados."
            };
            return (normalizedType, tag, skipped, SafeReadClassification.Invalid);
        }

        var safety = F6201BTagSafety.Classify(tag);
        if (safety.Blocked || LooksLikeActionUrl(html, normalizedType, tag))
        {
            var blocked = itemBase with
            {
                Classification = SafeReadClassification.BlockedPotentialAction,
                ClassificationReason = safety.Blocked
                    ? safety.Reason
                    : "URL associada a query extra além de _type/_tag/Menu3Location."
            };
            return (normalizedType, tag, blocked, SafeReadClassification.BlockedPotentialAction);
        }

        if (folder)
        {
            var folderItem = itemBase with
            {
                Classification = SafeReadClassification.UnknownNotAccessed,
                ClassificationReason = "Nó de pasta do menu; GET não iniciado sem evidência de folha."
            };
            return (normalizedType, tag, folderItem, SafeReadClassification.UnknownNotAccessed);
        }

        var safe = itemBase with
        {
            Classification = SafeReadClassification.SafeRead,
            ClassificationReason = "Referenciada explicitamente na interface autenticada, sem token de ação."
        };
        return (normalizedType, tag, safe, SafeReadClassification.SafeRead);
    }

    private static bool LooksLikeActionUrl(string html, string type, string tag)
    {
        var needle = $"_type={type}&_tag={tag}&";
        var idx = html.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return false;
        }

        var window = html.Substring(idx, Math.Min(120, html.Length - idx));
        return ExtraQuery.IsMatch(window);
    }

    private static IReadOnlyList<(string Id, string Kind, string Path)> ExtractMenuNodes(string html)
    {
        var json = ExtractJsonArray(html, "menuTreeJSON");
        if (json is null)
        {
            return [];
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var nodes = new List<(string Id, string Kind, string Path)>();
            Walk(document.RootElement, nodes, parentPath: string.Empty);
            return nodes;
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static void Walk(JsonElement element, List<(string Id, string Kind, string Path)> nodes, string parentPath)
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
            nodes.Add((id, kind, path));
        }

        if (hasChildren)
        {
            Walk(children, nodes, path);
        }
    }

    private static string? ExtractJsonArray(string html, string variableName)
    {
        var needle = variableName + " =";
        var idx = html.IndexOf(needle, StringComparison.Ordinal);
        if (idx < 0)
        {
            needle = variableName + "=";
            idx = html.IndexOf(needle, StringComparison.Ordinal);
        }

        if (idx < 0)
        {
            return null;
        }

        var start = html.IndexOf('[', idx);
        if (start < 0)
        {
            return null;
        }

        var depth = 0;
        for (var i = start; i < html.Length; i++)
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
                    return html[start..(i + 1)];
                }
            }
        }

        return null;
    }
}
