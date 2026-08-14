using System.Net;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record HomologatedReadExecution(
    IReadOnlyList<(string Page, string Body)> Pages,
    IReadOnlyList<string> PageNames,
    IReadOnlyList<SafeReadInventoryItem> Inventory,
    IReadOnlyList<HomologatedGetTrace> Traces,
    IReadOnlyList<FieldReadResult> FieldReads,
    F6201BParsedDeviceInformation Device,
    F6201BParsedPonStatus Pon,
    F6201BParsedWanSummary Wan,
    FirmwareCompatibility FirmwareCompatibility,
    bool SessionCookiesPreserved);

public static class F6201BHomologatedReadCoordinator
{
    public static async Task<HomologatedReadExecution> ReadAsync(
        IBoundOntTransport transport,
        CancellationToken cancellationToken)
    {
        var pages = new List<(string Page, string Body)>();
        var pageNames = new List<string>();
        var traces = new List<HomologatedGetTrace>();
        var inventory = new List<SafeReadInventoryItem>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var cookieAtStart = transport.HasSessionCookie;
        var genericScreens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var screen in F6201BV9310P8N1HomologatedReadContract.Screens)
        {
            await FetchAsync(
                transport,
                screen.Template,
                visited,
                pages,
                pageNames,
                traces,
                inventory,
                parseBody: false,
                cancellationToken);

            var data = await FetchAsync(
                transport,
                screen.Data,
                visited,
                pages,
                pageNames,
                traces,
                inventory,
                parseBody: true,
                cancellationToken);

            if (data.Generic)
            {
                genericScreens.Add(screen.Screen);
            }

            if (data.Incompatible)
            {
                break;
            }
        }

        var device = F6201BV9310P8N1DeviceInformationParser.Parse(pages.ToArray());
        var pon = F6201BV9310P8N1PonParser.Parse(pages.ToArray());
        var wan = F6201BV9310P8N1WanParser.Parse(pages.ToArray());
        var compatibility = F6201BFirmwareCompatibility.Classify(device.SoftwareVersion);
        var fields = BuildFields(device, pon, wan, traces, compatibility, genericScreens);
        return new HomologatedReadExecution(
            pages,
            pageNames,
            inventory,
            traces,
            fields,
            device,
            pon,
            wan,
            compatibility,
            transport.HasSessionCookie == cookieAtStart || transport.HasSessionCookie);
    }

    private static async Task<(bool Generic, bool Incompatible)> FetchAsync(
        IBoundOntTransport transport,
        HomologatedGetRoute route,
        HashSet<string> visited,
        List<(string Page, string Body)> pages,
        List<string> pageNames,
        List<HomologatedGetTrace> traces,
        List<SafeReadInventoryItem> inventory,
        bool parseBody,
        CancellationToken cancellationToken)
    {
        transport.RememberProvenQueryParameters(route.Type, route.Tag, route.FixedExtras);
        var path = F6201BV9310P8N1HomologatedReadContract.BuildPath(
            route,
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString());
        var identity = F6201BGetUrl.Identity(path);
        if (!visited.Add(identity))
        {
            traces.Add(Trace(
                transport.BoundAddress,
                route,
                path,
                0,
                null,
                F6201BAjaxXml.Inspect(null),
                [],
                route.ExpectedFields.ToList(),
                "duplicado normalizado ignorado"));
            return (false, false);
        }

        var item = F6201BV9310P8N1HomologatedReadContract.ToInventory(route);
        var page = await transport.GetAsync(path, cancellationToken);
        if (!page.Succeeded)
        {
            inventory.Add(item.WithClassification(
                SafeReadClassification.UnknownNotAccessed,
                page.Error?.Message ?? "GET homologado falhou; a sessão autenticada foi preservada.",
                false) with
            {
                HttpStatus = page.StatusCode
            });
            traces.Add(Trace(
                transport.BoundAddress,
                route,
                path,
                page.StatusCode,
                page.ContentType,
                F6201BAjaxXml.Inspect(null),
                [],
                route.ExpectedFields.ToList(),
                "resposta parcial"));
            return (false, false);
        }

        pageNames.Add(path);
        inventory.Add(item.WithAccess(page.ContentType, page.Body.Length, page.SanitizedBodySha256) with
        {
            HttpStatus = page.StatusCode
        });

        var structure = F6201BAjaxXml.Inspect(page.Body);
        if (!parseBody)
        {
            traces.Add(Trace(
                transport.BoundAddress,
                route,
                path,
                page.StatusCode,
                page.ContentType,
                structure,
                [],
                [],
                "template menuView"));
            return (false, false);
        }

        if (structure.IsGenericAck || !F6201BAjaxXml.SatisfiesContract(page.Body, route.CharacteristicMarkers))
        {
            var recognized = Recognized(route, page.Body);
            traces.Add(Trace(
                transport.BoundAddress,
                route,
                path,
                page.StatusCode,
                page.ContentType,
                structure,
                recognized,
                route.ExpectedFields.ToList(),
                structure.IsGenericAck ? "GenericXmlResponse" : "ContractNotSatisfied"));
            return (true, false);
        }

        pages.Add((path, page.Body));
        var deviceSoFar = F6201BV9310P8N1DeviceInformationParser.Parse(pages.ToArray());
        var compatibilitySoFar = F6201BFirmwareCompatibility.Classify(deviceSoFar.SoftwareVersion);
        var found = Recognized(route, page.Body);
        var missing = route.ExpectedFields.Where(field => !found.Contains(field, StringComparer.OrdinalIgnoreCase)).ToList();
        traces.Add(Trace(
            transport.BoundAddress,
            route,
            path,
            page.StatusCode,
            page.ContentType,
            structure,
            found,
            missing,
            compatibilitySoFar == FirmwareCompatibility.ConfirmedIncompatible ? "firmware incompatível" : "lido"));
        return (false, compatibilitySoFar == FirmwareCompatibility.ConfirmedIncompatible);
    }

    private static HomologatedGetTrace Trace(
        IPAddress boundAddress,
        HomologatedGetRoute route,
        string path,
        int status,
        string? contentType,
        SanitizedAjaxXmlStructure structure,
        IReadOnlyList<string> recognized,
        IReadOnlyList<string> missing,
        string outcome)
        => new(
            route.Screen,
            F6201BV9310P8N1AuthContract.MaskUri(ToUri(boundAddress, path)),
            route.Type,
            route.Tag,
            route.ExtraNames,
            status,
            contentType,
            structure.SizeBytes,
            structure.ShortHash,
            recognized,
            missing,
            outcome,
            structure.ToOperatorText());

    private static Uri ToUri(IPAddress boundAddress, string path)
        => Uri.TryCreate($"https://{boundAddress}{path}", UriKind.Absolute, out var uri)
            ? uri
            : new Uri($"https://{boundAddress}/");

    private static IReadOnlyList<string> Recognized(HomologatedGetRoute route, string body)
    {
        var found = new List<string>();
        foreach (var field in route.ExpectedFields)
        {
            var parsed = F6201BLabeledValueReader.ReadExact(route.LogicalEndpoint, body, field);
            if (parsed.Found)
            {
                found.Add(field);
            }
        }

        foreach (var obj in F6201BLabeledValueReader.ReadXmlInstances(body))
        {
            foreach (var field in route.ExpectedFields)
            {
                if (found.Contains(field, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (obj.Keys.Any(key => F6201BFieldAssociation.NamesEqual(key, field) && !F6201BLabeledValueReader.IsPasswordKey(key)))
                {
                    found.Add(field);
                }
            }
        }

        return found;
    }

    private static IReadOnlyList<FieldReadResult> BuildFields(
        F6201BParsedDeviceInformation device,
        F6201BParsedPonStatus pon,
        F6201BParsedWanSummary wan,
        IReadOnlyList<HomologatedGetTrace> traces,
        FirmwareCompatibility compatibility,
        IReadOnlySet<string> genericScreens)
    {
        var deviceTrace = traces.LastOrDefault(item => item.Screen == "Device" && item.Type == "menuData");
        var ponTrace = traces.LastOrDefault(item => item.Screen == "PON" && item.Type == "menuData");
        var wanTraces = traces.Where(item => item.Screen.StartsWith("WAN", StringComparison.Ordinal) && item.Type == "menuData").ToList();
        var devicePartial = deviceTrace?.Outcome == "resposta parcial";
        var ponPartial = ponTrace?.Outcome == "resposta parcial";
        var wanPartial = wanTraces.Count > 0 && wanTraces.All(item => item.Outcome == "resposta parcial");

        var list = new List<FieldReadResult>
        {
            Field("Device Type", device.DeviceType, deviceTrace, device.Evidence, devicePartial, compatibility, genericScreens.Contains("Device"), value => value ?? string.Empty),
            Field("Hardware Version", device.HardwareVersion, deviceTrace, device.Evidence, devicePartial, compatibility, genericScreens.Contains("Device"), value => value ?? string.Empty),
            Field("Software Version", device.SoftwareVersion, deviceTrace, device.Evidence, devicePartial, compatibility, genericScreens.Contains("Device"), value => value ?? string.Empty),
            Field("Boot Version", device.BootVersion, deviceTrace, device.Evidence, devicePartial, compatibility, genericScreens.Contains("Device"), value => value ?? string.Empty),
            Field("Serial Number", device.SerialNumber, deviceTrace, device.Evidence, devicePartial, compatibility, genericScreens.Contains("Device"), SensitiveDataMasker.MaskSerial),
            Field("MAC Address", device.MacAddress, deviceTrace, device.Evidence, devicePartial, compatibility, genericScreens.Contains("Device"), SensitiveDataMasker.MaskMac),
            Field("ONU State", pon.OnuState, ponTrace, pon.Evidence, ponPartial, compatibility, genericScreens.Contains("PON"), value => value ?? string.Empty),
            Field("Input Power", pon.InputPower, ponTrace, pon.Evidence, ponPartial, compatibility, genericScreens.Contains("PON"), value => value ?? string.Empty),
            Field("Output Power", pon.OutputPower, ponTrace, pon.Evidence, ponPartial, compatibility, genericScreens.Contains("PON"), value => value ?? string.Empty),
            Field("Supply Voltage", pon.Voltage, ponTrace, pon.Evidence, ponPartial, compatibility, genericScreens.Contains("PON"), value => value ?? string.Empty),
            Field("Transmitter Bias Current", pon.BiasCurrent, ponTrace, pon.Evidence, ponPartial, compatibility, genericScreens.Contains("PON"), value => value ?? string.Empty),
            Field("Temperature", pon.Temperature, ponTrace, pon.Evidence, ponPartial, compatibility, genericScreens.Contains("PON"), value => value ?? string.Empty),
            Field("LOID", pon.Loid, ponTrace, pon.Evidence, ponPartial, compatibility, genericScreens.Contains("PON"), SensitiveDataMasker.MaskUsername)
        };

        if (wan.Profiles.Count == 0)
        {
            var wanGeneric = genericScreens.Contains("WAN Status") || genericScreens.Contains("WAN Config");
            list.Add(Field("WAN profiles", null, wanTraces.FirstOrDefault(), wan.Evidence, wanPartial, compatibility, wanGeneric, value => value ?? string.Empty));
        }

        return list;
    }

    private static FieldReadResult Field(
        string name,
        string? value,
        HomologatedGetTrace? trace,
        IReadOnlyList<FieldEvidence> evidence,
        bool pagePartial,
        FirmwareCompatibility compatibility,
        bool genericXml,
        Func<string?, string> sanitize)
    {
        if (compatibility == FirmwareCompatibility.ConfirmedIncompatible
            && name is not "Software Version" and not "Device Type" and not "Hardware Version" and not "Boot Version" and not "Serial Number" and not "MAC Address")
        {
            return new FieldReadResult(name, null, trace?.LogicalEndpoint, "leitura encerrada", FieldReadStatus.ConfirmedIncompatible);
        }

        if (genericXml && string.IsNullOrWhiteSpace(value))
        {
            return new FieldReadResult(
                name,
                null,
                trace?.LogicalEndpoint,
                trace?.XmlStructure,
                FieldReadStatus.ContractNotSatisfied);
        }

        if (pagePartial && string.IsNullOrWhiteSpace(value))
        {
            return new FieldReadResult(name, null, trace?.LogicalEndpoint, "HTTP da página falhou", FieldReadStatus.Partial);
        }

        var match = evidence.FirstOrDefault(item =>
            F6201BFieldAssociation.NamesEqual(item.Field, name) || F6201BFieldAssociation.NamesEqual(item.FieldKey, name));
        if (string.IsNullOrWhiteSpace(value))
        {
            return new FieldReadResult(name, null, trace?.LogicalEndpoint, match?.Strategy, FieldReadStatus.NotFound);
        }

        return new FieldReadResult(
            name,
            sanitize(value),
            match?.SourcePage ?? trace?.LogicalEndpoint,
            match?.Strategy ?? "xml-paraname",
            FieldReadStatus.Read);
    }
}
