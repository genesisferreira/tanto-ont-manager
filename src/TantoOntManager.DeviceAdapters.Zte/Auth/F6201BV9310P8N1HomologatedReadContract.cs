using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record HomologatedGetRoute(
    string Screen,
    string Type,
    string Tag,
    IReadOnlyDictionary<string, string> FixedExtras,
    IReadOnlyList<string> ExpectedFields,
    IReadOnlyList<string> CharacteristicMarkers)
{
    public string LogicalEndpoint => F6201BV9310P8N1AuthContract.MakeKey(Type, Tag);

    public string ExtraNames => string.Join(",", new[] { "_" }.Concat(FixedExtras.Keys));
}

public sealed record HomologatedScreenContract(
    string Screen,
    HomologatedGetRoute Template,
    HomologatedGetRoute Data);

public static class F6201BV9310P8N1HomologatedReadContract
{
    public const string ReadAdapterId = "zte-f6201b-v9.3.10p8n1-read-v1";
    public const string Firmware = F6201BV9310P8N1AuthContract.ExpectedSoftware;
    public const string Model = "F6201B";
    public const string Manufacturer = "ZTE";
    public const string JqueryAjaxHeaderName = "X-Requested-With";
    public const string JqueryAjaxHeaderValue = "XMLHttpRequest";

    private static readonly Dictionary<string, string> Menu3Location =
        new(StringComparer.OrdinalIgnoreCase) { ["Menu3Location"] = "0" };

    private static readonly Dictionary<string, string> WanStatusExtras =
        new(StringComparer.OrdinalIgnoreCase) { ["TypeUplink"] = "2", ["pageType"] = "1" };

    private static readonly Dictionary<string, string> WanConfigExtras =
        new(StringComparer.OrdinalIgnoreCase) { ["TypeUplink"] = "2", ["pageType"] = "0" };

    public static readonly HomologatedGetRoute DeviceTemplate = new(
        "Device",
        "menuView",
        "statusMgr",
        Menu3Location,
        [],
        []);

    public static readonly HomologatedGetRoute Device = new(
        "Device",
        "menuData",
        "devmgr_statusmgr_lua.lua",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
        ["Device Type", "Hardware Version", "Software Version", "Boot Version", "Serial Number", "MAC Address"],
        ["OBJ_DEVINFO_ID"]);

    public static readonly HomologatedGetRoute PonTemplate = new(
        "PON",
        "menuView",
        "ponopticalinfo",
        Menu3Location,
        [],
        []);

    public static readonly HomologatedGetRoute Pon = new(
        "PON",
        "menuData",
        "optical_info_lua.lua",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
        ["ONU State", "Input Power", "Output Power", "Supply Voltage", "Transmitter Bias Current", "Temperature", "LOID", "GPON SN"],
        ["OBJ_PON_OPTICALPARA_ID"]);

    public static readonly HomologatedGetRoute WanStatusTemplate = new(
        "WAN Status",
        "menuView",
        "ethWanStatus",
        Menu3Location,
        [],
        []);

    public static readonly HomologatedGetRoute WanStatus = new(
        "WAN Status",
        "menuData",
        "wan_internetstatus_lua.lua",
        WanStatusExtras,
        ["WANCName", "ConnStatus", "IPAddress", "MACAddress"],
        ["ID_WAN_COMFIG"]);

    public static readonly HomologatedGetRoute WanConfigTemplate = new(
        "WAN Config",
        "menuView",
        "ethWanConfig",
        Menu3Location,
        [],
        []);

    public static readonly HomologatedGetRoute WanConfig = new(
        "WAN Config",
        "menuData",
        "wan_internet_lua.lua",
        WanConfigExtras,
        ["WANCName", "VLANID", "ServList", "ConnType"],
        ["ID_WAN_COMFIG"]);

    public static IReadOnlyList<HomologatedScreenContract> Screens { get; } =
    [
        new("Device", DeviceTemplate, Device),
        new("PON", PonTemplate, Pon),
        new("WAN Status", WanStatusTemplate, WanStatus),
        new("WAN Config", WanConfigTemplate, WanConfig)
    ];

    public static IReadOnlyList<HomologatedGetRoute> Routes { get; } =
        Screens.SelectMany(screen => new[] { screen.Template, screen.Data }).ToList();

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
            route.Type == "menuView" ? "homologated-menuview-contract" : "homologated-get-contract",
            "GET",
            null,
            0,
            string.Empty,
            SafeReadClassification.SafeRead,
            route.Type == "menuView"
                ? "Template menuView observado imediatamente antes do menuData na homologação 0.1.6.2-lab."
                : "Rota GET comprovada na homologação 0.1.6.2-lab.",
            false)
        {
            TypeAndTag = route.LogicalEndpoint,
            ExtraParameters = route.FixedExtras,
            RouteKind = route.Type == "menuView" ? AuthenticatedRouteKind.MenuLeaf : AuthenticatedRouteKind.DataEndpoint,
            MenuText = route.Screen
        };
}
