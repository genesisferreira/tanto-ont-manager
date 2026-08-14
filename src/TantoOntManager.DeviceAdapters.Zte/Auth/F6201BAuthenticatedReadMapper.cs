using Microsoft.Extensions.Logging;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record AuthenticatedReadMapResult(
    AuthenticatedReadMap Map,
    AuthenticatedReadSnapshot Snapshot);

public static class F6201BAuthenticatedReadMapper
{
    public static async Task<AuthenticatedReadMapResult> MapAsync(
        IBoundOntTransport transport,
        AuthenticatedReadSnapshot current,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var home = await transport.GetAsync("/", cancellationToken);
        var pages = new List<(string Page, string Body)>();
        var sources = new List<(string Page, string Body)>();
        var templates = RouteTemplateSet.Empty;

        if (home.Succeeded)
        {
            pages.Add(("/", home.Body));
            sources.Add(("/", home.Body));
            templates = templates.Union(F6201BStaticRouteResolver.DetectTemplates(home.Body));
        }

        if (home.Succeeded)
        {
            var scripts = F6201BScriptReference.Extract(
                home.Body,
                transport.BoundAddress,
                new Uri($"https://{transport.BoundAddress}/"),
                F6201BV9310P8N1AuthContract.MaxJsAssets);
            foreach (var script in scripts)
            {
                transport.RememberReferencedAsset(script);
                var js = await transport.GetAsync(script, cancellationToken);
                Log(logger, "asset", System.IO.Path.GetFileNameWithoutExtension(script), js, SafeReadClassification.SafeRead);
                if (!js.Succeeded)
                {
                    continue;
                }

                sources.Add((script, js.Body));
                templates = templates.Union(F6201BStaticRouteResolver.DetectTemplates(js.Body));
            }
        }

        var inventory = new List<SafeReadInventoryItem>();
        foreach (var source in sources)
        {
            inventory = F6201BSafeReadDiscovery.Merge(
                inventory,
                F6201BSafeReadDiscovery.Discover(source.Body, source.Page, templates)).ToList();
        }

        Remember(transport, inventory);

        var directed = await F6201BDirectedReadCoordinator.ExecuteAsync(
            transport,
            inventory,
            sources,
            pages.Select(item => (item.Page, item.Body, item.Page == "/" ? home.SanitizedBodySha256 : string.Empty)).ToList(),
            templates,
            logger,
            cancellationToken);

        pages = directed.Pages.Select(item => (item.Page, item.Body)).ToList();
        sources = directed.Sources;
        templates = directed.Templates;
        inventory = directed.Inventory;
        var accessed = directed.Accessed;

        var mergedInventory = inventory.Select(item =>
            accessed.TryGetValue(item.TypeAndTag, out var updated) ? updated with { MenuText = updated.MenuText ?? item.MenuText } : item).ToList();

        var entries = mergedInventory.Select(item => ToEntry(item, accessed)).ToList();
        var found = F6201BPriorityMenu.All.Where(label => entries.Any(entry => entry.IsPriority && F6201BPriorityMenu.Match(entry.MenuText) == label)).Distinct().ToList();
        var missing = F6201BPriorityMenu.All.Except(found).ToList();
        var unresolved = CollectUnresolved(sources, mergedInventory);

        var device = F6201BV9310P8N1DeviceInformationParser.Parse(pages.ToArray());
        var pon = F6201BV9310P8N1PonParser.Parse(pages.ToArray());
        var wan = F6201BV9310P8N1WanParser.Parse(pages.ToArray());
        var identity = MergeIdentity(current.Identity, device);
        var diagnostics = MergeDiagnostics(current.Diagnostics, pon, wan);

        var hashes = directed.Pages.ToDictionary(item => item.Page, item => item.Hash, StringComparer.OrdinalIgnoreCase);
        var evidence = device.Evidence.Concat(pon.Evidence).Concat(wan.Evidence)
            .Select(item => item with { ResponseHash = hashes.GetValueOrDefault(item.SourcePage) ?? item.ResponseHash })
            .ToList();
        var note = BuildNote(found, missing, unresolved, entries, device, pon, wan);
        var map = new AuthenticatedReadMap(
            entries,
            unresolved,
            found,
            missing,
            transport.LoginPostCount,
            transport.LogoutPostCount,
            transport.ConfigPostCount,
            note)
        {
            DirectedReads = directed.Steps
        };

        var snapshot = current with
        {
            Identity = identity,
            Diagnostics = diagnostics,
            PagesRead = pages.Select(item => item.Page).Distinct().ToList(),
            Inventory = mergedInventory,
            FieldEvidence = evidence,
            LoginPostCount = transport.LoginPostCount,
            LogoutPostCount = transport.LogoutPostCount,
            ConfigPostCount = transport.ConfigPostCount,
            PostCount = transport.PostCount,
            FirmwareCompatibility = F6201BFirmwareCompatibility.Classify(identity)
        };

        return new AuthenticatedReadMapResult(map, snapshot);
    }

    private static AuthenticatedReadMapEntry ToEntry(
        SafeReadInventoryItem item,
        IReadOnlyDictionary<string, SafeReadInventoryItem> accessed)
    {
        var resolved = accessed.TryGetValue(item.TypeAndTag, out var updated) ? updated : item;
        var parts = resolved.TypeAndTag.Split(':');
        var type = parts.Length > 0 ? parts[0] : "menuView";
        var tag = parts.Length > 1 ? parts[1] : resolved.Tag;
        if (string.Equals(type, "unresolved", StringComparison.OrdinalIgnoreCase))
        {
            type = "—";
            tag = resolved.Variable ?? resolved.Tag;
        }

        return new AuthenticatedReadMapEntry(
            resolved.MenuText ?? item.MenuText,
            type,
            tag,
            resolved.EvidenceSource,
            resolved.Classification,
            resolved.ClassificationReason,
            resolved.WasAccessed ? resolved.HttpStatus ?? 200 : resolved.HttpStatus,
            resolved.ContentType,
            resolved.SizeBytes,
            string.IsNullOrWhiteSpace(resolved.SanitizedHash) ? null : resolved.SanitizedHash,
            resolved.WasAccessed,
            F6201BPriorityMenu.Match(resolved.MenuText ?? item.MenuText) is not null)
        {
            RouteKind = resolved.RouteKind,
            Confidence = resolved.Confidence,
            Variable = resolved.Variable,
            LiteralValue = resolved.LiteralValue,
            SanitizedSnippet = resolved.SanitizedSnippet,
            ExtraParametersText = F6201BProvenQueryParameter.Format(resolved.ExtraParameters)
        };
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

    private static IReadOnlyList<string> CollectUnresolved(
        IEnumerable<(string Page, string Body)> sources,
        IReadOnlyList<SafeReadInventoryItem> inventory)
    {
        var hasMenuLeaf = inventory.Any(item => item.RouteKind == AuthenticatedRouteKind.MenuLeaf
                                                && item.Classification == SafeReadClassification.SafeRead);
        var found = new List<string>();
        foreach (var source in sources)
        {
            var resolved = F6201BStaticRouteResolver.Resolve(source.Body, source.Page);
            foreach (var reason in resolved.UnresolvedReasons)
            {
                if (hasMenuLeaf
                    && reason.Contains("menuView", StringComparison.OrdinalIgnoreCase)
                    && reason.Contains("sem literal", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!found.Contains(reason, StringComparer.Ordinal))
                {
                    found.Add(reason);
                }
            }

            foreach (var pattern in F6201BUnresolvedPatterns.Find(source.Body))
            {
                if (hasMenuLeaf && pattern.Contains("menuView", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!found.Contains(pattern, StringComparer.Ordinal))
                {
                    found.Add(pattern);
                }
            }
        }

        return found;
    }

    private static void Log(ILogger logger, string type, string tag, BoundHttpResult page, SafeReadClassification classification)
    {
        logger.LogInformation(
            "Mapa autenticado type={Type} tag={Tag} status={Status} tamanho={Size} hash={Hash} classificacao={Kind}",
            type,
            tag,
            page.StatusCode,
            page.Body.Length,
            page.SanitizedBodySha256,
            classification);
    }

    private static DeviceIdentity MergeIdentity(DeviceIdentity previous, F6201BParsedDeviceInformation parsed)
    {
        var next = F6201BV9310P8N1AuthenticatedPageParser.ToIdentity(
            previous.Manufacturer,
            previous.Model,
            parsed);
        return new DeviceIdentity(
            previous.Manufacturer,
            next.Model ?? previous.Model,
            new FirmwareInfo(
                next.Firmware.SoftwareVersion ?? previous.Firmware.SoftwareVersion,
                next.Firmware.HardwareVersion ?? previous.Firmware.HardwareVersion,
                next.Firmware.BootVersion ?? previous.Firmware.BootVersion),
            next.SerialNumber ?? previous.SerialNumber,
            next.MacAddress ?? previous.MacAddress);
    }

    private static DeviceDiagnostics MergeDiagnostics(
        DeviceDiagnostics previous,
        F6201BParsedPonStatus pon,
        F6201BParsedWanSummary wan)
    {
        var next = F6201BV9310P8N1AuthenticatedPageParser.ToDiagnostics(pon, wan);
        var profiles = next.WanProfiles.Count > 0 ? next.WanProfiles : previous.WanProfiles;
        return previous with
        {
            Pon = next.Pon.OnuState is null ? previous.Pon : next.Pon,
            Optical = next.Optical.RxPower is null && next.Optical.TxPower is null ? previous.Optical : next.Optical,
            WanProfiles = profiles,
            WanSummary = next.WanSummary ?? previous.WanSummary
        };
    }

    private static string BuildNote(
        IReadOnlyList<string> found,
        IReadOnlyList<string> missing,
        IReadOnlyList<string> unresolved,
        IReadOnlyList<AuthenticatedReadMapEntry> entries,
        F6201BParsedDeviceInformation device,
        F6201BParsedPonStatus pon,
        F6201BParsedWanSummary wan)
    {
        var parts = new List<string>();
        if (missing.Count > 0)
        {
            parts.Add("Telas prioritárias sem evidência de menu: " + string.Join("; ", missing) + ". Nenhum endpoint foi adivinhado.");
        }

        if (found.Count > 0)
        {
            parts.Add("Telas prioritárias evidenciadas: " + string.Join("; ", found) + ".");
        }

        var realLabels = entries
            .Select(item => item.MenuText)
            .Where(text => !string.IsNullOrWhiteSpace(text))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (missing.Count > 0 && realLabels.Count > 0)
        {
            parts.Add("Rótulos reais do menu: " + string.Join("; ", realLabels) + ".");
        }

        if (unresolved.Count > 0)
        {
            parts.Add("Rotas concatenadas sem origem literal permaneceram UnresolvedDynamicRoute; o pareamento não foi inventado.");
        }

        var empty = string.IsNullOrWhiteSpace(device.HardwareVersion)
                    && string.IsNullOrWhiteSpace(device.SoftwareVersion)
                    && string.IsNullOrWhiteSpace(pon.OnuState)
                    && wan.Profiles.Count == 0;
        if (empty)
        {
            parts.Add("Nenhuma página evidenciada continha os campos Device/PON/WAN conhecidos.");
        }

        return parts.Count == 0
            ? "Mapa construído somente com evidências literais da sessão autenticada."
            : string.Join(" ", parts);
    }
}
