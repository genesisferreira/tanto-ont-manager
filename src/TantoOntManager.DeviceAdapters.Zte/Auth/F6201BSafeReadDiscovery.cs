using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BSafeReadDiscovery
{
    public static IReadOnlyList<SafeReadInventoryItem> Discover(
        string? html,
        string evidencePage = "/",
        RouteTemplateSet extraTemplates = default)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return [];
        }

        var items = new List<SafeReadInventoryItem>();
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var templates = F6201BStaticRouteResolver.DetectTemplates(html).Union(extraTemplates);
        var menuByTag = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        void Add(SafeReadInventoryItem item)
        {
            var key = string.IsNullOrWhiteSpace(item.TypeAndTag)
                ? "unresolved:" + (item.Variable ?? item.Tag)
                : item.TypeAndTag;
            if (!seenKeys.Add(key))
            {
                var idx = items.FindIndex(candidate => candidate.TypeAndTag.Equals(key, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                {
                    items[idx] = Enrich(items[idx], item);
                }

                return;
            }

            items.Add(item);
        }

        foreach (var node in F6201BMenuTreeExtractor.Extract(html))
        {
            if (!string.IsNullOrWhiteSpace(node.Path))
            {
                menuByTag[node.Id] = node.Path;
            }

            var extras = node.Kind == "page" ? F6201BStaticRouteResolver.Menu3Extras(templates) : new Dictionary<string, string>();
            Add(Classify(
                "menuView",
                node.Id,
                $"menuTreeJSON:{node.Kind}@{evidencePage}",
                node.Path,
                folder: node.Kind == "folder",
                extras,
                F6201BStaticRouteResolver.KindOf("menuView", node.Id, node.Kind == "folder"),
                RouteConfidence.High,
                "id",
                node.Id,
                "{id,name,children,area}",
                node.Kind == "folder"
                    ? "Nó de pasta do menuTreeJSON; GET não iniciado sem evidência de folha."
                    : "id literal do menuTreeJSON associado ao template menuView."));
        }

        var resolved = F6201BStaticRouteResolver.Resolve(html, evidencePage, templates);
        foreach (var route in resolved.Routes)
        {
            if (route.Unresolved)
            {
                Add(new SafeReadInventoryItem(
                    route.Variable ?? "unresolved",
                    route.EvidenceSource,
                    "GET",
                    null,
                    0,
                    string.Empty,
                    SafeReadClassification.UnknownNotAccessed,
                    route.Reason,
                    false)
                {
                    TypeAndTag = "unresolved:" + (route.Variable ?? "route"),
                    MenuText = route.MenuText,
                    RouteKind = AuthenticatedRouteKind.UnresolvedDynamicRoute,
                    Confidence = RouteConfidence.None,
                    Variable = route.Variable,
                    LiteralValue = route.LiteralValue,
                    SanitizedSnippet = route.SanitizedSnippet
                });
                continue;
            }

            menuByTag.TryGetValue(route.Tag, out var path);
            Add(Classify(
                route.Type,
                route.Tag,
                route.EvidenceSource,
                route.MenuText ?? path,
                route.Folder,
                route.ExtraParameters,
                route.Kind,
                route.Confidence,
                route.Variable,
                route.LiteralValue,
                route.SanitizedSnippet,
                route.Reason));
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
                var idx = result.FindIndex(candidate => candidate.TypeAndTag.Equals(key, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                {
                    result[idx] = item.WasAccessed ? item : Enrich(result[idx], item);
                }

                continue;
            }

            result.Add(item);
        }

        return Prioritize(result);
    }

    private static SafeReadInventoryItem Enrich(SafeReadInventoryItem current, SafeReadInventoryItem incoming)
    {
        return current with
        {
            MenuText = current.MenuText ?? incoming.MenuText,
            ExtraParameters = F6201BProvenQueryParameter.Merge(current.ExtraParameters, incoming.ExtraParameters),
            Variable = current.Variable ?? incoming.Variable,
            LiteralValue = current.LiteralValue ?? incoming.LiteralValue,
            SanitizedSnippet = string.IsNullOrWhiteSpace(current.SanitizedSnippet) ? incoming.SanitizedSnippet : current.SanitizedSnippet,
            Confidence = incoming.Confidence > current.Confidence ? incoming.Confidence : current.Confidence,
            RouteKind = incoming.RouteKind == AuthenticatedRouteKind.UnresolvedDynamicRoute
                ? current.RouteKind
                : current.RouteKind == default
                    ? incoming.RouteKind
                    : current.RouteKind
        };
    }

    private static IReadOnlyList<SafeReadInventoryItem> Prioritize(IReadOnlyList<SafeReadInventoryItem> items)
    {
        return items
            .Select((item, index) => (item, index))
            .OrderBy(tuple => F6201BFirmwareCompatibility.SafeReadOrder(tuple.item))
            .ThenBy(tuple => tuple.index)
            .Select(tuple => tuple.item)
            .ToList();
    }

    private static SafeReadInventoryItem Classify(
        string type,
        string tag,
        string source,
        string? menuText,
        bool folder,
        IReadOnlyDictionary<string, string> extras,
        AuthenticatedRouteKind kind,
        RouteConfidence confidence,
        string? variable,
        string? literal,
        string? snippet,
        string reason)
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
            MenuText = menuText,
            ExtraParameters = extras,
            RouteKind = kind,
            Confidence = confidence,
            Variable = variable,
            LiteralValue = literal,
            SanitizedSnippet = snippet
        };

        if (!F6201BV9310P8N1AuthContract.IsValidTag(tag)
            || !F6201BV9310P8N1AuthContract.IsAllowedGetType(normalizedType))
        {
            return itemBase with
            {
                Classification = SafeReadClassification.Invalid,
                ClassificationReason = "Tag ou tipo GET inválido."
            };
        }

        if (F6201BV9310P8N1AuthContract.IsAuthControlTag(tag))
        {
            return itemBase with
            {
                Classification = SafeReadClassification.Invalid,
                ClassificationReason = "Tag de controle de autenticação; não é leitura de dados."
            };
        }

        var safety = F6201BTagSafety.Classify(tag);
        if (safety.Blocked)
        {
            return itemBase with
            {
                Classification = SafeReadClassification.BlockedPotentialAction,
                ClassificationReason = safety.Reason,
                RouteKind = AuthenticatedRouteKind.ActionEndpoint
            };
        }

        if (F6201BTagSafety.HasConfigToken(tag) && !F6201BTagSafety.IsMenuViewConfigTemplate(normalizedType, tag))
        {
            return itemBase with
            {
                Classification = SafeReadClassification.BlockedPotentialAction,
                ClassificationReason = "GET de dados de configuração não comprovado como leitura; apenas menuView GET de template é permitido.",
                RouteKind = AuthenticatedRouteKind.ActionEndpoint
            };
        }

        if (F6201BTagSafety.IsMenuViewConfigTemplate(normalizedType, tag))
        {
            return itemBase with
            {
                Classification = SafeReadClassification.SafeRead,
                ClassificationReason = "GET de template evidenciado no menu; escrita permanece bloqueada.",
                RouteKind = AuthenticatedRouteKind.MenuLeaf
            };
        }

        if (folder || kind == AuthenticatedRouteKind.MenuFolder)
        {
            return itemBase with
            {
                Classification = SafeReadClassification.UnknownNotAccessed,
                ClassificationReason = string.IsNullOrWhiteSpace(reason)
                    ? "Nó de pasta do menu; GET não iniciado sem evidência de folha."
                    : reason,
                RouteKind = AuthenticatedRouteKind.MenuFolder
            };
        }

        if (kind == AuthenticatedRouteKind.UnresolvedDynamicRoute)
        {
            return itemBase with
            {
                Classification = SafeReadClassification.UnknownNotAccessed,
                ClassificationReason = reason,
                RouteKind = AuthenticatedRouteKind.UnresolvedDynamicRoute,
                Confidence = RouteConfidence.None
            };
        }

        return itemBase with
        {
            Classification = SafeReadClassification.SafeRead,
            ClassificationReason = string.IsNullOrWhiteSpace(reason)
                ? "Referenciada explicitamente na interface autenticada, sem token de ação."
                : reason,
            RouteKind = kind == default ? F6201BStaticRouteResolver.KindOf(normalizedType, tag, false) : kind
        };
    }
}
