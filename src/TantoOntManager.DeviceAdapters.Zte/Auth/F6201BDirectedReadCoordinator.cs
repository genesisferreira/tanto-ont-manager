using Microsoft.Extensions.Logging;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public enum DirectedReadPriority
{
    Device = 0,
    Pon = 1,
    Wan = 2,
    Secondary = 3
}

public sealed record DirectedReadExecution(
    List<(string Page, string Body, string Hash)> Pages,
    List<(string Page, string Body)> Sources,
    Dictionary<string, SafeReadInventoryItem> Accessed,
    List<SafeReadInventoryItem> Inventory,
    RouteTemplateSet Templates,
    IReadOnlyList<DirectedReadStep> Steps,
    HashSet<string> VisitedUrls);

public static class F6201BDirectedReadCoordinator
{
    public static async Task<DirectedReadExecution> ExecuteAsync(
        IBoundOntTransport transport,
        IReadOnlyList<SafeReadInventoryItem> initialInventory,
        IReadOnlyList<(string Page, string Body)> initialSources,
        IReadOnlyList<(string Page, string Body, string Hash)> initialPages,
        RouteTemplateSet templates,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var pages = initialPages.ToList();
        var sources = initialSources.ToList();
        var inventory = initialInventory.ToList();
        var accessed = new Dictionary<string, SafeReadInventoryItem>(StringComparer.OrdinalIgnoreCase);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queued = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var steps = new List<DirectedReadStep>();
        foreach (var page in pages)
        {
            visited.Add(F6201BGetUrl.Normalize(page.Page));
        }

        Remember(transport, inventory);

        templates = await RunPriorityAsync(
            DirectedReadPriority.Device,
            F6201BV9310P8N1AuthContract.DirectedDeviceGets,
            transport,
            inventory,
            accessed,
            visited,
            queued,
            pages,
            sources,
            templates,
            steps,
            logger,
            cancellationToken);

        var deviceSoFar = F6201BV9310P8N1DeviceInformationParser.Parse(pages.Select(item => (item.Page, item.Body)).ToArray());
        if (F6201BFirmwareCompatibility.Classify(deviceSoFar.SoftwareVersion) != FirmwareCompatibility.ConfirmedIncompatible)
        {
            templates = await RunPriorityAsync(
                DirectedReadPriority.Pon,
                F6201BV9310P8N1AuthContract.DirectedPonGets,
                transport,
                inventory,
                accessed,
                visited,
                queued,
                pages,
                sources,
                templates,
                steps,
                logger,
                cancellationToken);

            templates = await RunPriorityAsync(
                DirectedReadPriority.Wan,
                F6201BV9310P8N1AuthContract.DirectedWanGets,
                transport,
                inventory,
                accessed,
                visited,
                queued,
                pages,
                sources,
                templates,
                steps,
                logger,
                cancellationToken);

            templates = await RunPriorityAsync(
                DirectedReadPriority.Secondary,
                F6201BV9310P8N1AuthContract.SecondaryGets,
                transport,
                inventory,
                accessed,
                visited,
                queued,
                pages,
                sources,
                templates,
                steps,
                logger,
                cancellationToken);
        }

        return new DirectedReadExecution(pages, sources, accessed, inventory, templates, steps, visited);
    }

    public static DirectedReadPriority Classify(SafeReadInventoryItem item)
    {
        if (IsDevice(item))
        {
            return DirectedReadPriority.Device;
        }

        if (IsPon(item))
        {
            return DirectedReadPriority.Pon;
        }

        if (IsWan(item))
        {
            return DirectedReadPriority.Wan;
        }

        return DirectedReadPriority.Secondary;
    }

    private static async Task<RouteTemplateSet> RunPriorityAsync(
        DirectedReadPriority priority,
        int budget,
        IBoundOntTransport transport,
        List<SafeReadInventoryItem> inventory,
        Dictionary<string, SafeReadInventoryItem> accessed,
        HashSet<string> visited,
        HashSet<string> queued,
        List<(string Page, string Body, string Hash)> pages,
        List<(string Page, string Body)> sources,
        RouteTemplateSet templates,
        List<DirectedReadStep> steps,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var used = 0;
        var pending = inventory
            .Where(item => item.Classification == SafeReadClassification.SafeRead)
            .Where(item => item.RouteKind is not AuthenticatedRouteKind.MenuFolder
                and not AuthenticatedRouteKind.UnresolvedDynamicRoute
                and not AuthenticatedRouteKind.ActionEndpoint)
            .Where(item => priority == DirectedReadPriority.Secondary || Classify(item) == priority)
            .Where(item => !accessed.ContainsKey(item.TypeAndTag))
            .OrderBy(item => SeedOrder(item, priority))
            .ToList();

        foreach (var item in pending)
        {
            queued.Add(item.TypeAndTag);
        }

        string? start = pending.FirstOrDefault()?.TypeAndTag;
        string? data = null;
        string? missing = pending.Count == 0 ? "Nenhuma folha literal desta prioridade no menu." : null;

        while (pending.Count > 0 && used < budget && pages.Count < F6201BV9310P8N1AuthContract.MaxMappedPages)
        {
            var candidate = pending[0];
            pending.RemoveAt(0);
            if (accessed.ContainsKey(candidate.TypeAndTag))
            {
                continue;
            }

            var parts = candidate.TypeAndTag.Split(':');
            var type = parts[0];
            var tag = parts.Length > 1 ? parts[1] : candidate.Tag;
            if (priority != DirectedReadPriority.Wan
                && F6201BTagSafety.HasConfigToken(tag)
                && !F6201BTagSafety.IsMenuViewConfigTemplate(type, tag))
            {
                continue;
            }

            transport.RememberProvenQueryParameters(type, tag, candidate.ExtraParameters);
            var path = F6201BV9310P8N1AuthContract.BuildGetPath(type, tag, candidate.ExtraParameters);
            var normalized = F6201BGetUrl.Normalize(path);
            if (!visited.Add(normalized))
            {
                accessed[candidate.TypeAndTag] = candidate.WithClassification(
                    SafeReadClassification.Duplicate,
                    "URL GET idêntica já lida nesta sessão.",
                    true);
                continue;
            }

            var page = await transport.GetAsync(path, cancellationToken);
            logger.LogInformation(
                "Leitura dirigida prioridade={Priority} type={Type} tag={Tag} status={Status} hash={Hash}",
                priority,
                type,
                tag,
                page.StatusCode,
                page.SanitizedBodySha256);
            used++;
            start ??= candidate.TypeAndTag;

            if (!page.Succeeded)
            {
                accessed[candidate.TypeAndTag] = candidate.WithClassification(
                    SafeReadClassification.UnknownNotAccessed,
                    page.Error?.Message ?? "GET autenticado não concluído; sessão mantida.",
                    false) with
                {
                    MenuText = candidate.MenuText,
                    HttpStatus = page.StatusCode == 0 ? null : page.StatusCode
                };
                missing ??= page.Error?.Message ?? "GET autenticado não concluído.";
                continue;
            }

            if (F6201BHtmlText.LooksLikeLoginInsteadOfInternalPage(page.Body))
            {
                accessed[candidate.TypeAndTag] = candidate.WithClassification(
                    SafeReadClassification.UnknownNotAccessed,
                    "Resposta parece login; página não interpretada como dado interno. Sessão mantida.",
                    false) with
                {
                    MenuText = candidate.MenuText,
                    HttpStatus = page.StatusCode
                };
                missing ??= "Resposta parece login.";
                continue;
            }

            pages.Add((path, page.Body, page.SanitizedBodySha256));
            sources.Add((path, page.Body));
            templates = templates.Union(F6201BStaticRouteResolver.DetectTemplates(page.Body));
            accessed[candidate.TypeAndTag] = candidate.WithAccess(page.ContentType, page.Body.Length, page.SanitizedBodySha256) with
            {
                MenuText = candidate.MenuText,
                HttpStatus = page.StatusCode
            };

            if (candidate.RouteKind == AuthenticatedRouteKind.DataEndpoint
                || string.Equals(type, "menuData", StringComparison.OrdinalIgnoreCase)
                || string.Equals(type, "hiddenData", StringComparison.OrdinalIgnoreCase))
            {
                data ??= path;
            }

            var discovered = F6201BSafeReadDiscovery.Discover(page.Body, path, templates)
                .Where(item => item.EvidenceSource.Contains(path, StringComparison.OrdinalIgnoreCase)
                               || item.EvidenceSource.Contains(tag, StringComparison.OrdinalIgnoreCase))
                .ToList();
            var merged = F6201BSafeReadDiscovery.Merge(inventory, discovered).ToList();
            inventory.Clear();
            inventory.AddRange(merged);
            Remember(transport, discovered);

            var followUps = discovered
                .Where(item => item.Classification == SafeReadClassification.SafeRead)
                .Where(item => item.RouteKind is AuthenticatedRouteKind.DataEndpoint or AuthenticatedRouteKind.MenuLeaf)
                .Where(item => Classify(item) == priority || item.RouteKind == AuthenticatedRouteKind.DataEndpoint)
                .Where(item => FollowsPriority(item, priority))
                .ToList();

            foreach (var item in followUps)
            {
                if (queued.Add(item.TypeAndTag) && !accessed.ContainsKey(item.TypeAndTag))
                {
                    pending.Insert(0, item);
                }
            }
        }

        var result = accessed.Values.Any(item => item.WasAccessed && Classify(item) == priority)
            ? "lidas"
            : "sem dados";
        if (pending.Count == 0 && used == 0)
        {
            result = "ausente";
        }

        steps.Add(new DirectedReadStep(
            priority.ToString(),
            start ?? "—",
            data,
            result,
            missing,
            used,
            budget));
        return templates;
    }

    private static int SeedOrder(SafeReadInventoryItem item, DirectedReadPriority priority)
    {
        if (priority == DirectedReadPriority.Device && item.Tag.Equals("statusMgr", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        if (priority == DirectedReadPriority.Pon)
        {
            if (item.Tag.Equals("ponOpticalInfo", StringComparison.OrdinalIgnoreCase)
                || item.Tag.Equals("ponopticalinfo", StringComparison.OrdinalIgnoreCase))
            {
                return 0;
            }

            if (item.Tag.Equals("ponSn", StringComparison.OrdinalIgnoreCase))
            {
                return 1;
            }

            if (item.Tag.Equals("ponLoid", StringComparison.OrdinalIgnoreCase))
            {
                return 2;
            }
        }

        if (priority == DirectedReadPriority.Wan && item.Tag.Equals("ethWanStatus", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        return item.RouteKind == AuthenticatedRouteKind.MenuLeaf ? 3 : 4;
    }

    private static bool FollowsPriority(SafeReadInventoryItem item, DirectedReadPriority priority)
        => priority switch
        {
            DirectedReadPriority.Device => IsDevice(item) || item.RouteKind is AuthenticatedRouteKind.DataEndpoint or AuthenticatedRouteKind.HomepageShell,
            DirectedReadPriority.Pon => IsPon(item) || item.RouteKind == AuthenticatedRouteKind.DataEndpoint,
            DirectedReadPriority.Wan => IsWan(item) || item.RouteKind == AuthenticatedRouteKind.DataEndpoint,
            _ => item.RouteKind is AuthenticatedRouteKind.DataEndpoint
                or AuthenticatedRouteKind.MenuLeaf
                or AuthenticatedRouteKind.HomepageShell
        };

    private static bool IsDevice(SafeReadInventoryItem item)
        => F6201BFirmwareCompatibility.LooksLikeDeviceInformation(item)
           || item.Tag.Equals("statusMgr", StringComparison.OrdinalIgnoreCase)
           || item.RouteKind == AuthenticatedRouteKind.HomepageShell;

    private static bool IsPon(SafeReadInventoryItem item)
    {
        var tag = item.Tag;
        if (tag.Equals("ponOpticalInfo", StringComparison.OrdinalIgnoreCase)
            || tag.Equals("ponopticalinfo", StringComparison.OrdinalIgnoreCase)
            || tag.Equals("ponSn", StringComparison.OrdinalIgnoreCase)
            || tag.Equals("ponLoid", StringComparison.OrdinalIgnoreCase)
            || tag.Equals("ponInfo", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return F6201BPriorityMenu.Match(item.MenuText) == F6201BPriorityMenu.PonInformation
               || (item.MenuText ?? string.Empty).Contains("PON Inform", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsWan(SafeReadInventoryItem item)
    {
        var tag = item.Tag;
        if (tag.Equals("ethWanStatus", StringComparison.OrdinalIgnoreCase)
            || tag.Equals("ethWan", StringComparison.OrdinalIgnoreCase)
            || (tag.Equals("ethWanConfig", StringComparison.OrdinalIgnoreCase)
                && F6201BTagSafety.IsMenuViewConfigTemplate(item.TypeAndTag.Split(':')[0], tag)))
        {
            return true;
        }

        var menu = F6201BPriorityMenu.Match(item.MenuText);
        return menu is F6201BPriorityMenu.Wan or F6201BPriorityMenu.WanUnderStatus;
    }

    private static void Remember(IBoundOntTransport transport, IEnumerable<SafeReadInventoryItem> items)
    {
        foreach (var item in items.Where(candidate => candidate.Classification == SafeReadClassification.SafeRead))
        {
            var parts = item.TypeAndTag.Split(':');
            if (parts.Length == 2)
            {
                transport.RememberProvenQueryParameters(parts[0], parts[1], item.ExtraParameters);
            }
        }
    }
}
