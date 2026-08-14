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
        var unresolved = new List<string>();
        var accessed = new Dictionary<string, SafeReadInventoryItem>(StringComparer.OrdinalIgnoreCase);

        if (home.Succeeded)
        {
            pages.Add(("/", home.Body));
            CollectUnresolved(unresolved, home.Body);
        }

        var inventory = home.Succeeded
            ? F6201BSafeReadDiscovery.Discover(home.Body, "/").ToList()
            : [];

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

                CollectUnresolved(unresolved, js.Body);
                var fromJs = F6201BSafeReadDiscovery.Discover(js.Body, script);
                inventory = F6201BSafeReadDiscovery.Merge(inventory, fromJs).ToList();
            }
        }

        Remember(transport, inventory);

        var pending = inventory
            .Where(item => item.Classification == SafeReadClassification.SafeRead)
            .OrderBy(item => F6201BPriorityMenu.Match(item.MenuText) is null ? 1 : 0)
            .ToList();

        var totalBytes = pages.Sum(item => item.Body.Length);
        foreach (var candidate in pending)
        {
            if (pages.Count >= F6201BV9310P8N1AuthContract.MaxSafeReadPages
                || totalBytes >= F6201BV9310P8N1AuthContract.MaxTotalBodyBytes)
            {
                break;
            }

            var parts = candidate.TypeAndTag.Split(':');
            var type = parts[0];
            var tag = parts.Length > 1 ? parts[1] : candidate.Tag;
            transport.RememberSafeRead(type, tag);
            var path = F6201BV9310P8N1AuthContract.BuildGetPath(type, tag);
            var page = await transport.GetAsync(path, cancellationToken);
            Log(logger, type, tag, page, candidate.Classification);
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
                continue;
            }

            totalBytes += page.Body.Length;
            pages.Add((path, page.Body));
            CollectUnresolved(unresolved, page.Body);
            accessed[candidate.TypeAndTag] = candidate.WithAccess(page.ContentType, page.Body.Length, page.SanitizedBodySha256) with
            {
                MenuText = candidate.MenuText,
                HttpStatus = page.StatusCode
            };
            var discovered = F6201BSafeReadDiscovery.Discover(page.Body, path);
            inventory = F6201BSafeReadDiscovery.Merge(inventory, discovered).ToList();
            Remember(transport, discovered);
        }

        var mergedInventory = inventory.Select(item =>
            accessed.TryGetValue(item.TypeAndTag, out var updated) ? updated with { MenuText = updated.MenuText ?? item.MenuText } : item).ToList();

        var entries = mergedInventory.Select(item => ToEntry(item, accessed)).ToList();
        var found = F6201BPriorityMenu.All.Where(label => entries.Any(entry => entry.IsPriority && F6201BPriorityMenu.Match(entry.MenuText) == label)).Distinct().ToList();
        var missing = F6201BPriorityMenu.All.Except(found).ToList();

        var device = F6201BV9310P8N1DeviceInformationParser.Parse(pages.ToArray());
        var pon = F6201BV9310P8N1PonParser.Parse(pages.ToArray());
        var wan = F6201BV9310P8N1WanParser.Parse(pages.ToArray());
        var identity = MergeIdentity(current.Identity, device);
        var diagnostics = MergeDiagnostics(current.Diagnostics, pon, wan);

        var note = BuildNote(found, missing, unresolved, device, pon, wan);
        var map = new AuthenticatedReadMap(
            entries,
            unresolved.Distinct(StringComparer.Ordinal).ToList(),
            found,
            missing,
            transport.LoginPostCount,
            transport.LogoutPostCount,
            transport.ConfigPostCount,
            note);

        var snapshot = current with
        {
            Identity = identity,
            Diagnostics = diagnostics,
            PagesRead = pages.Select(item => item.Page).Distinct().ToList(),
            Inventory = mergedInventory,
            FieldEvidence = device.Evidence.Concat(pon.Evidence).Concat(wan.Evidence).ToList(),
            LoginPostCount = transport.LoginPostCount,
            LogoutPostCount = transport.LogoutPostCount,
            ConfigPostCount = transport.ConfigPostCount,
            PostCount = transport.PostCount
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
            F6201BPriorityMenu.Match(resolved.MenuText ?? item.MenuText) is not null);
    }

    private static void Remember(IBoundOntTransport transport, IEnumerable<SafeReadInventoryItem> items)
    {
        foreach (var item in items.Where(candidate => candidate.Classification == SafeReadClassification.SafeRead))
        {
            var parts = item.TypeAndTag.Split(':');
            if (parts.Length == 2)
            {
                transport.RememberSafeRead(parts[0], parts[1]);
            }
        }
    }

    private static void CollectUnresolved(List<string> target, string body)
    {
        foreach (var pattern in F6201BUnresolvedPatterns.Find(body))
        {
            if (!target.Contains(pattern, StringComparer.Ordinal))
            {
                target.Add(pattern);
            }
        }
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

        if (unresolved.Count > 0)
        {
            parts.Add("O JS descreve GET concatenado sem tag literal; o pareamento não foi inventado.");
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
