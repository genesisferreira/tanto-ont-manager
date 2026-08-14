using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record AuthenticatedSafeReadResult(
    IReadOnlyList<(string Page, string Body)> Pages,
    IReadOnlyList<SafeReadInventoryItem> Inventory,
    IReadOnlyList<string> PageNames,
    bool SessionExpired,
    int TotalBytes);

public static class F6201BAuthenticatedSafeReader
{
    public static async Task<AuthenticatedSafeReadResult> ReadAsync(
        IBoundOntTransport transport,
        string homeHtml,
        string homePath,
        BoundHttpResult homeResult,
        CancellationToken cancellationToken)
    {
        var pages = new List<(string Page, string Body)> { (homePath, homeHtml) };
        var pageNames = new List<string> { homePath };
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { homeResult.SanitizedBodySha256 };
        var inventory = F6201BSafeReadDiscovery.Discover(homeHtml, homePath).ToList();
        Remember(transport, inventory);
        var totalBytes = homeHtml.Length;
        var accessed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { F6201BV9310P8N1AuthContract.MakeKey("home", "/") };

        var pending = inventory
            .Where(item => item.Classification == SafeReadClassification.SafeRead)
            .ToList();

        while (pending.Count > 0
               && pages.Count < F6201BV9310P8N1AuthContract.MaxSafeReadPages
               && totalBytes < F6201BV9310P8N1AuthContract.MaxTotalBodyBytes)
        {
            var next = pending[0];
            pending.RemoveAt(0);
            var key = next.TypeAndTag;
            if (!accessed.Add(key))
            {
                Mark(inventory, key, item => item.WithClassification(
                    SafeReadClassification.Duplicate,
                    "Página já acessada nesta sessão.",
                    item.WasAccessed));
                continue;
            }

            var type = key.Split(':')[0];
            var tag = next.Tag;
            var path = F6201BV9310P8N1AuthContract.BuildGetPath(type, tag);
            var page = await transport.GetAsync(path, cancellationToken);
            if (!page.Succeeded)
            {
                if (page.Error?.Code is ErrorCodes.GetNotAllowlisted or ErrorCodes.DestructivePageBlocked)
                {
                    Mark(inventory, key, item => item.WithClassification(
                        SafeReadClassification.BlockedPotentialAction,
                        page.Error.Message,
                        false));
                    continue;
                }

                return new AuthenticatedSafeReadResult(pages, inventory, pageNames, false, totalBytes);
            }

            if (F6201BHtmlText.LooksLikeLoginInsteadOfInternalPage(page.Body))
            {
                Mark(inventory, key, item => item.WithClassification(
                    SafeReadClassification.UnknownNotAccessed,
                    "Resposta parece login ou sessão inválida; a página não foi interpretada como dado interno.",
                    false));
                continue;
            }

            totalBytes += page.Body.Length;
            if (totalBytes > F6201BV9310P8N1AuthContract.MaxTotalBodyBytes)
            {
                Mark(inventory, key, item => item.WithClassification(
                    SafeReadClassification.UnknownNotAccessed,
                    "Limite de bytes da sessão autenticada atingido.",
                    false));
                break;
            }

            if (!hashes.Add(page.SanitizedBodySha256))
            {
                Mark(inventory, key, item => item.WithClassification(
                    SafeReadClassification.Duplicate,
                    "Conteúdo sanitizado duplicado; nova leitura evitada.",
                    true).WithAccess(page.ContentType, page.Body.Length, page.SanitizedBodySha256));
                continue;
            }

            pages.Add((path, page.Body));
            pageNames.Add(path);
            var accessedItem = next.WithAccess(page.ContentType, page.Body.Length, page.SanitizedBodySha256);
            Replace(inventory, key, accessedItem);

            var discovered = F6201BSafeReadDiscovery.Discover(page.Body, path);
            inventory = F6201BSafeReadDiscovery.Merge(inventory, discovered).ToList();
            Remember(transport, discovered);
            foreach (var item in discovered.Where(candidate => candidate.Classification == SafeReadClassification.SafeRead))
            {
                if (!accessed.Contains(item.TypeAndTag)
                    && pending.All(candidate => !candidate.TypeAndTag.Equals(item.TypeAndTag, StringComparison.OrdinalIgnoreCase)))
                {
                    pending.Add(item);
                }
            }
        }

        foreach (var leftover in pending)
        {
            Mark(inventory, leftover.TypeAndTag, item => item.Classification == SafeReadClassification.SafeRead && !item.WasAccessed
                ? item.WithClassification(
                    SafeReadClassification.UnknownNotAccessed,
                    "Não acessada por limite de páginas ou bytes.",
                    false)
                : item);
        }

        return new AuthenticatedSafeReadResult(pages, inventory, pageNames, false, totalBytes);
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

    private static void Mark(
        List<SafeReadInventoryItem> inventory,
        string key,
        Func<SafeReadInventoryItem, SafeReadInventoryItem> update)
    {
        var idx = inventory.FindIndex(item => item.TypeAndTag.Equals(key, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0)
        {
            inventory[idx] = update(inventory[idx]);
        }
    }

    private static void Replace(List<SafeReadInventoryItem> inventory, string key, SafeReadInventoryItem value)
    {
        var idx = inventory.FindIndex(item => item.TypeAndTag.Equals(key, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0)
        {
            inventory[idx] = value;
        }
        else
        {
            inventory.Add(value);
        }
    }
}
