using System.Text.RegularExpressions;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Security.Export;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public readonly record struct RouteTemplateSet(
    bool MenuViewPlusVariable,
    bool MenuDataPlusVariable,
    bool HiddenDataPlusVariable,
    bool OpenLinkTakesPageurl,
    bool MenuPageUsesMenu3Location,
    string? Menu3LocationValue)
{
    public static RouteTemplateSet Empty => default;

    public RouteTemplateSet Union(RouteTemplateSet other)
        => new(
            MenuViewPlusVariable || other.MenuViewPlusVariable,
            MenuDataPlusVariable || other.MenuDataPlusVariable,
            HiddenDataPlusVariable || other.HiddenDataPlusVariable,
            OpenLinkTakesPageurl || other.OpenLinkTakesPageurl,
            MenuPageUsesMenu3Location || other.MenuPageUsesMenu3Location,
            Menu3LocationValue ?? other.Menu3LocationValue);
}

public sealed record ResolvedStaticRoute(
    string Type,
    string Tag,
    IReadOnlyDictionary<string, string> ExtraParameters,
    AuthenticatedRouteKind Kind,
    RouteConfidence Confidence,
    string EvidenceSource,
    string? MenuText,
    string? Variable,
    string? LiteralValue,
    string SanitizedSnippet,
    string Reason,
    bool Folder,
    bool Unresolved);

public sealed record StaticRouteResolution(
    IReadOnlyList<ResolvedStaticRoute> Routes,
    IReadOnlyList<string> UnresolvedReasons,
    RouteTemplateSet Templates);

public static class F6201BStaticRouteResolver
{
    public const bool UsesEvalOrJsEngine = false;
    private const int MaxBindings = 200;
    private const int MaxRoutes = 100;

    private static readonly HashSet<string> TagVariableNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "pageurl", "page", "MenuPage", "tag", "PageName"
    };

    private static readonly Regex LiteralAssign = new(
        @"(?:(?:var|let|const)\s+)?(?:this\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['""])([A-Za-z][A-Za-z0-9_\-]*)\2",
        RegexOptions.Compiled);

    private static readonly Regex LiteralConcatAssign = new(
        @"(?:(?:var|let|const)\s+)?(?:this\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['""])([^'""]*)\2\s*\+\s*(['""])([^'""]*)\4",
        RegexOptions.Compiled);

    private static readonly Regex AliasAssign = new(
        @"(?:(?:var|let|const)\s+)?(?:this\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
        RegexOptions.Compiled);

    private static readonly Regex VarConcatAssign = new(
        @"(?:(?:var|let|const)\s+)?(?:this\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
        RegexOptions.Compiled);

    private static readonly Regex ObjectTagProperty = new(
        @"(?:pageurl|page|MenuPage|tag)\s*:\s*['""]([A-Za-z][A-Za-z0-9_\-]*)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex TaintAssign = new(
        @"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*\(|[^;]*(?:\.val\s*\(|prompt\s*\(|userInput|Frm_Username|Frm_Password|eval\s*\())",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ConcatTag = new(
        @"[""']/\?_type=(menuView|menuData|hiddenData)&_tag=[""']\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s*\+\s*[""']([^""']+)[""'])?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex LiteralUrl = new(
        @"[""']/\?_type=(menuView|menuData|hiddenData)&_tag=([A-Za-z][A-Za-z0-9_\-]*)([^""']*)[""']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex OpenLinkLiteral = new(
        @"openLink\(\s*['""]([A-Za-z][A-Za-z0-9_\-]*)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex OpenLinkVariable = new(
        @"openLink\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*[,)]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MenuPageAttr = new(
        @"MenuPage\s*=\s*['""]([A-Za-z][A-Za-z0-9_\-]*)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MenuViewConcat = new(
        @"_type=menuView&_tag=\s*[""']?\s*\+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MenuDataConcat = new(
        @"_type=menuData&_tag=\s*[""']?\s*\+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HiddenDataConcat = new(
        @"_type=hiddenData&_tag=\s*[""']?\s*\+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex OpenLinkSignature = new(
        @"function\s+openLink\s*\(\s*pageurl",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex Menu3LocationLiteral = new(
        @"&Menu3Location=([0-9]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static RouteTemplateSet DetectTemplates(string? source)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return RouteTemplateSet.Empty;
        }

        string? menu3 = null;
        var menu3Match = Menu3LocationLiteral.Match(source);
        if (menu3Match.Success)
        {
            menu3 = menu3Match.Groups[1].Value;
        }

        var usesMenu3 = MenuViewConcat.IsMatch(source) && menu3 is not null
                        && source.Contains("MenuPage", StringComparison.Ordinal);
        return new RouteTemplateSet(
            MenuViewConcat.IsMatch(source),
            MenuDataConcat.IsMatch(source),
            HiddenDataConcat.IsMatch(source),
            OpenLinkSignature.IsMatch(source),
            usesMenu3,
            usesMenu3 ? menu3 : null);
    }

    public static StaticRouteResolution Resolve(
        string? source,
        string evidencePage = "/",
        RouteTemplateSet extraTemplates = default)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return new StaticRouteResolution([], [], extraTemplates);
        }

        var templates = DetectTemplates(source).Union(extraTemplates);
        var bindings = CollectBindings(source);
        var routes = new List<ResolvedStaticRoute>();
        var unresolved = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(ResolvedStaticRoute route)
        {
            if (routes.Count >= MaxRoutes)
            {
                return;
            }

            var key = route.Unresolved
                ? $"unresolved:{route.Type}:{route.Variable}"
                : F6201BV9310P8N1AuthContract.MakeKey(route.Type, route.Tag) + "|" + F6201BProvenQueryParameter.Format(route.ExtraParameters);
            if (!seen.Add(key))
            {
                return;
            }

            routes.Add(route);
        }

        foreach (Match match in LiteralUrl.Matches(source))
        {
            var type = match.Groups[1].Value;
            var tag = match.Groups[2].Value;
            var tail = match.Groups[3].Value;
            if (!TryParseLiteralTail(tail, out var extras, out var dynamicTail))
            {
                if (dynamicTail)
                {
                    Add(Unresolved(type, match.Groups[2].Value, evidencePage, match.Value, "Parâmetro extra dinâmico; rota não acessada."));
                    unresolved.Add($"Parâmetro extra dinâmico em {type}:{tag}.");
                }

                continue;
            }

            Add(Route(
                type,
                tag,
                extras,
                KindOf(type, tag, folder: false),
                RouteConfidence.High,
                $"literalUrl@{evidencePage}",
                null,
                null,
                tag,
                Snippet(source, match.Index),
                "URL GET com _type/_tag literais comprovados.",
                folder: false));
        }

        foreach (Match match in ConcatTag.Matches(source))
        {
            var type = match.Groups[1].Value;
            var variable = match.Groups[2].Value;
            var tail = match.Groups[3].Success ? match.Groups[3].Value : string.Empty;
            if (bindings.Tainted.Contains(variable))
            {
                Add(Unresolved(type, variable, evidencePage, match.Value, $"Variável {variable} vem de função ou entrada do usuário."));
                unresolved.Add($"Variável {variable} dinâmica; {type} não resolvido.");
                continue;
            }

            if (!TryParseLiteralTail(tail, out var extras, out var dynamicTail) || dynamicTail)
            {
                Add(Unresolved(type, variable, evidencePage, match.Value, "Sufixo de query dinâmico ou inseguro."));
                unresolved.Add($"Concatenação {type} com parâmetro extra não literal.");
                continue;
            }

            if (!bindings.Literals.TryGetValue(variable, out var literal))
            {
                Add(Unresolved(type, variable, evidencePage, match.Value, $"Variável {variable} sem origem literal comprovada."));
                unresolved.Add($"Concatenação {type}+{variable} sem literal.");
                continue;
            }

            Add(Route(
                type,
                literal,
                extras,
                KindOf(type, literal, folder: false),
                RouteConfidence.Medium,
                $"concat:{variable}@{evidencePage}",
                null,
                variable,
                literal,
                Snippet(source, match.Index),
                $"Concatenação segura: URL fixa + {variable}='{literal}'.",
                folder: false));
        }

        foreach (Match match in OpenLinkLiteral.Matches(source))
        {
            var tag = match.Groups[1].Value;
            Add(Route(
                "menuView",
                tag,
                NoExtras(),
                KindOf("menuView", tag, folder: false),
                RouteConfidence.High,
                $"openLink@{evidencePage}",
                null,
                "pageurl",
                tag,
                Snippet(source, match.Index),
                "openLink com tag literal.",
                folder: false));
        }

        foreach (Match match in OpenLinkVariable.Matches(source))
        {
            var variable = match.Groups[1].Value;
            if (bindings.Tainted.Contains(variable))
            {
                Add(Unresolved("menuView", variable, evidencePage, match.Value, $"openLink({variable}) com origem dinâmica."));
                unresolved.Add($"openLink({variable}) dinâmico.");
                continue;
            }

            if (bindings.Literals.TryGetValue(variable, out var literal))
            {
                Add(Route(
                    "menuView",
                    literal,
                    NoExtras(),
                    KindOf("menuView", literal, folder: false),
                    RouteConfidence.Medium,
                    $"openLink:{variable}@{evidencePage}",
                    null,
                    variable,
                    literal,
                    Snippet(source, match.Index),
                    $"openLink({variable}) com literal '{literal}'.",
                    folder: false));
            }
        }

        foreach (Match match in MenuPageAttr.Matches(source))
        {
            var tag = match.Groups[1].Value;
            var extras = Menu3Extras(templates);
            Add(Route(
                "menuView",
                tag,
                extras,
                AuthenticatedRouteKind.MenuLeaf,
                RouteConfidence.High,
                $"MenuPage@{evidencePage}",
                null,
                "MenuPage",
                tag,
                Snippet(source, match.Index),
                templates.MenuPageUsesMenu3Location
                    ? "MenuPage literal + Menu3Location literal comprovado."
                    : "Atributo MenuPage literal.",
                folder: false));
        }

        foreach (var pair in bindings.Literals)
        {
            if (!TagVariableNames.Contains(pair.Key) || routes.Count >= MaxRoutes)
            {
                continue;
            }

            Add(Route(
                "menuView",
                pair.Value,
                NoExtras(),
                KindOf("menuView", pair.Value, folder: false),
                RouteConfidence.High,
                $"assign:{pair.Key}@{evidencePage}",
                null,
                pair.Key,
                pair.Value,
                pair.Key + "=\"" + pair.Value + "\"",
                $"Atribuição literal local {pair.Key}='{pair.Value}'.",
                folder: false));
        }

        var filteredUnresolved = unresolved
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return new StaticRouteResolution(routes, filteredUnresolved, templates);
    }

    public static IReadOnlyDictionary<string, string> Menu3Extras(RouteTemplateSet templates)
    {
        if (!templates.MenuPageUsesMenu3Location
            || string.IsNullOrWhiteSpace(templates.Menu3LocationValue)
            || !F6201BProvenQueryParameter.TryCreate("Menu3Location", templates.Menu3LocationValue, out var name, out var value))
        {
            return new Dictionary<string, string>();
        }

        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [name] = value };
    }

    public static AuthenticatedRouteKind KindOf(string type, string tag, bool folder)
    {
        if (folder)
        {
            return AuthenticatedRouteKind.MenuFolder;
        }

        if (F6201BTagSafety.IsBlocked(tag))
        {
            return AuthenticatedRouteKind.ActionEndpoint;
        }

        if (tag.Contains("homepage", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticatedRouteKind.HomepageShell;
        }

        if (string.Equals(type, "menuView", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticatedRouteKind.MenuLeaf;
        }

        return AuthenticatedRouteKind.DataEndpoint;
    }

    private static Bindings CollectBindings(string source)
    {
        var tainted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in TaintAssign.Matches(source))
        {
            tainted.Add(match.Groups[1].Value);
        }

        var literals = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Bind(string name, string value)
        {
            if (literals.Count >= MaxBindings
                || tainted.Contains(name)
                || !F6201BV9310P8N1AuthContract.IsValidTag(value))
            {
                return;
            }

            literals[name] = value;
        }

        foreach (Match match in LiteralAssign.Matches(source))
        {
            Bind(match.Groups[1].Value, match.Groups[3].Value);
        }

        foreach (Match match in LiteralConcatAssign.Matches(source))
        {
            Bind(match.Groups[1].Value, match.Groups[3].Value + match.Groups[5].Value);
        }

        foreach (Match match in ObjectTagProperty.Matches(source))
        {
            Bind("pageurl", match.Groups[1].Value);
        }

        for (var hop = 0; hop < 3; hop++)
        {
            foreach (Match match in AliasAssign.Matches(source))
            {
                var left = match.Groups[1].Value;
                var right = match.Groups[2].Value;
                if (!tainted.Contains(left)
                    && !tainted.Contains(right)
                    && literals.TryGetValue(right, out var value))
                {
                    Bind(left, value);
                }
            }

            foreach (Match match in VarConcatAssign.Matches(source))
            {
                var left = match.Groups[1].Value;
                var a = match.Groups[2].Value;
                var b = match.Groups[3].Value;
                if (!tainted.Contains(left)
                    && literals.TryGetValue(a, out var leftVal)
                    && literals.TryGetValue(b, out var rightVal))
                {
                    Bind(left, leftVal + rightVal);
                }
            }
        }

        return new Bindings(literals, tainted);
    }

    private static bool TryParseLiteralTail(
        string tail,
        out Dictionary<string, string> extras,
        out bool dynamicTail)
    {
        extras = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        dynamicTail = false;
        if (string.IsNullOrWhiteSpace(tail))
        {
            return true;
        }

        var trimmed = tail.Trim();
        if (trimmed.Contains('+', StringComparison.Ordinal)
            || trimmed.Contains('\'', StringComparison.Ordinal)
            || trimmed.Contains('"', StringComparison.Ordinal)
            || trimmed.Contains('(', StringComparison.Ordinal))
        {
            dynamicTail = true;
            return false;
        }

        foreach (var part in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = part.IndexOf('=');
            if (idx <= 0)
            {
                dynamicTail = true;
                return false;
            }

            var name = part[..idx];
            var value = part[(idx + 1)..];
            if (!F6201BProvenQueryParameter.TryCreate(name, value, out var safeName, out var safeValue))
            {
                dynamicTail = true;
                return false;
            }

            extras[safeName] = safeValue;
        }

        return true;
    }

    private static ResolvedStaticRoute Route(
        string type,
        string tag,
        IReadOnlyDictionary<string, string> extras,
        AuthenticatedRouteKind kind,
        RouteConfidence confidence,
        string source,
        string? menuText,
        string? variable,
        string? literal,
        string snippet,
        string reason,
        bool folder)
        => new(
            type,
            tag,
            extras,
            kind,
            confidence,
            source,
            menuText,
            variable,
            literal,
            snippet,
            reason,
            folder,
            false);

    private static ResolvedStaticRoute Unresolved(
        string type,
        string variable,
        string evidencePage,
        string raw,
        string reason)
        => new(
            type,
            string.Empty,
            new Dictionary<string, string>(),
            AuthenticatedRouteKind.UnresolvedDynamicRoute,
            RouteConfidence.None,
            $"unresolved@{evidencePage}",
            null,
            variable,
            null,
            Snippet(raw, 0),
            reason,
            false,
            true);

    private static Dictionary<string, string> NoExtras()
        => new(StringComparer.OrdinalIgnoreCase);

    private static string Snippet(string source, int index)
    {
        var start = Math.Max(0, index);
        var length = Math.Min(96, source.Length - start);
        var raw = length <= 0 ? source : source.Substring(start, length);
        raw = Regex.Replace(raw, @"\s+", " ").Trim();
        return AuthenticatedPayloadSanitizer.Sanitize(raw);
    }

    private sealed record Bindings(
        Dictionary<string, string> Literals,
        HashSet<string> Tainted);
}
