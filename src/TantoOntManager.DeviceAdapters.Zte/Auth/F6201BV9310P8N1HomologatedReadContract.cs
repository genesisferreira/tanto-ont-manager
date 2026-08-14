using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record HomologatedGetRoute(
    string Screen,
    string Type,
    string Tag,
    IReadOnlyDictionary<string, string> FixedExtras,
    IReadOnlyList<string> ExpectedFields)
{
    public string LogicalEndpoint => F6201BV9310P8N1AuthContract.MakeKey(Type, Tag);

    public string ExtraNames => string.Join(",", new[] { "_" }.Concat(FixedExtras.Keys));
}

public static class F6201BV9310P8N1HomologatedReadContract
{
    public const string ReadAdapterId = "zte-f6201b-v9.3.10p8n1-read-v1";
    public const string Firmware = F6201BV9310P8N1AuthContract.ExpectedSoftware;
    public const string Model = "F6201B";
    public const string Manufacturer = "ZTE";

    public static readonly HomologatedGetRoute Device = new(
        "Device",
        "menuData",
        "devmgr_statusmgr_lua.lua",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
        ["Device Type", "Hardware Version", "Software Version", "Boot Version", "Serial Number", "MAC Address"]);

    public static readonly HomologatedGetRoute Pon = new(
        "PON",
        "menuData",
        "optical_info_lua.lua",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
        ["ONU State", "Input Power", "Output Power", "Supply Voltage", "Transmitter Bias Current", "Temperature"]);

    public static readonly HomologatedGetRoute WanStatus = new(
        "WAN Status",
        "menuData",
        "wan_internetstatus_lua.lua",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["TypeUplink"] = "2", ["pageType"] = "1" },
        ["WANCName", "ConnStatus", "IPAddress", "MACAddress"]);

    public static readonly HomologatedGetRoute WanConfig = new(
        "WAN Config",
        "menuData",
        "wan_internet_lua.lua",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["TypeUplink"] = "2", ["pageType"] = "0" },
        ["WANCName", "VLANID", "ServList", "ConnType"]);

    public static IReadOnlyList<HomologatedGetRoute> Routes { get; } = [Device, Pon, WanStatus, WanConfig];

    public static string BuildPath(HomologatedGetRoute route, string cacheBuster)
    {
        var extras = new Dictionary<string, string>(route.FixedExtras, StringComparer.OrdinalIgnoreCase)
        {
            ["_"] = cacheBuster
        };
        return F6201BV9310P8N1AuthContract.BuildGetPath(route.Type, route.Tag, extras);
    }

    public static SafeReadInventoryItem ToInventory(HomologatedGetRoute route)
        => new(
            route.Tag,
            "homologated-get-contract",
            "GET",
            null,
            0,
            string.Empty,
            SafeReadClassification.SafeRead,
            "Rota GET comprovada na homologação 0.1.6.2-lab.",
            false)
        {
            TypeAndTag = route.LogicalEndpoint,
            ExtraParameters = route.FixedExtras,
            RouteKind = AuthenticatedRouteKind.DataEndpoint,
            MenuText = route.Screen
        };
}
