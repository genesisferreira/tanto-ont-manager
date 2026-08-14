using System.Text.RegularExpressions;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Security.Export;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BFirmwareCompatibility
{
    private static readonly Regex SoftwarePattern = new(
        "^V\\d+\\.\\d+\\.\\d+P\\d+N\\d+$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly HashSet<string> UnavailableTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "NAODISPONIVELNAINTERFACEPUBLICA",
        "UNKNOWN",
        "DESCONHECIDO",
        "NA",
        "N/A",
        "NULL",
        "UNDEFINED",
        "NONE",
        "ND",
        "UNAVAILABLE",
        "INDISPONIVEL"
    };

    public static FirmwareCompatibility Classify(string? softwareVersion)
    {
        if (!TryGetReliableSoftwareVersion(softwareVersion, out var normalized))
        {
            return FirmwareCompatibility.Unconfirmed;
        }

        return normalized.Equals(F6201BV9310P8N1AuthContract.ExpectedSoftware, StringComparison.OrdinalIgnoreCase)
            ? FirmwareCompatibility.ConfirmedCompatible
            : FirmwareCompatibility.ConfirmedIncompatible;
    }

    public static FirmwareCompatibility Classify(DeviceIdentity identity)
        => Classify(identity.Firmware.SoftwareVersion);

    public static bool AllowsAuthenticationAndSafeRead(FirmwareCompatibility compatibility)
        => compatibility is FirmwareCompatibility.Unconfirmed or FirmwareCompatibility.ConfirmedCompatible;

    public static bool AllowsWrite(FirmwareCompatibility _)
        => false;

    public static bool TryGetReliableSoftwareVersion(string? softwareVersion, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(softwareVersion) || IsUnavailable(softwareVersion))
        {
            return false;
        }

        var compact = Normalize(softwareVersion).ToUpperInvariant();
        if (compact.Length == 0 || IsUnavailable(compact))
        {
            return false;
        }

        if (!compact.StartsWith('V'))
        {
            compact = "V" + compact;
        }

        if (!SoftwarePattern.IsMatch(compact))
        {
            return false;
        }

        normalized = compact.ToUpperInvariant();
        return true;
    }

    public static string SanitizeForOperator(string? softwareVersion)
    {
        if (!TryGetReliableSoftwareVersion(softwareVersion, out var normalized))
        {
            return "não confirmada";
        }

        return AuthenticatedPayloadSanitizer.Sanitize(normalized);
    }

    public static bool LooksLikeDeviceInformationPath(string? page)
    {
        if (string.IsNullOrWhiteSpace(page))
        {
            return false;
        }

        return page.Contains("devStatus", StringComparison.OrdinalIgnoreCase)
               || page.Contains("devinfo", StringComparison.OrdinalIgnoreCase)
               || page.Contains("statusMgr", StringComparison.OrdinalIgnoreCase)
               || page.Contains("devmgr_statusmgr", StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeDeviceInformationPage(string page, string? body)
    {
        if (LooksLikeDeviceInformationPath(page))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        if (body.Contains("OBJ_DEVINFO", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var compact = Regex.Replace(body, "[^A-Za-z0-9]", string.Empty);
        return compact.Contains("HardwareVer", StringComparison.OrdinalIgnoreCase)
               || compact.Contains("SoftwareVer", StringComparison.OrdinalIgnoreCase)
               || compact.Contains("FrmModelName", StringComparison.OrdinalIgnoreCase)
               || compact.Contains("FrmHardwareVer", StringComparison.OrdinalIgnoreCase)
               || compact.Contains("FrmSoftwareVer", StringComparison.OrdinalIgnoreCase)
               || compact.Contains("DeviceType", StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeDeviceInformation(SafeReadInventoryItem item)
    {
        var tag = item.Tag;
        if (tag.Equals("devStatus", StringComparison.OrdinalIgnoreCase)
            || tag.Equals("devinfo", StringComparison.OrdinalIgnoreCase)
            || tag.Equals("devInfo", StringComparison.OrdinalIgnoreCase)
            || tag.Equals("statusMgr", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var menu = item.MenuText ?? string.Empty;
        return menu.Contains("Device Information", StringComparison.OrdinalIgnoreCase)
               || F6201BPriorityMenu.Match(menu) == F6201BPriorityMenu.DeviceStatus;
    }

    public static int SafeReadOrder(SafeReadInventoryItem item)
    {
        if (item.Classification != SafeReadClassification.SafeRead)
        {
            return 80;
        }

        if (LooksLikeDeviceInformation(item))
        {
            return 0;
        }

        if (F6201BPriorityMenu.Match(item.MenuText) is not null)
        {
            return 1;
        }

        if (item.RouteKind == AuthenticatedRouteKind.MenuLeaf)
        {
            return 2;
        }

        if (item.RouteKind == AuthenticatedRouteKind.DataEndpoint)
        {
            return 3;
        }

        if (item.RouteKind == AuthenticatedRouteKind.HomepageShell)
        {
            return 5;
        }

        return 4;
    }

    private static bool IsUnavailable(string value)
    {
        var compact = Regex.Replace(value, "[^A-Za-z0-9]", string.Empty);
        if (compact.Length == 0)
        {
            return true;
        }

        return UnavailableTokens.Contains(compact);
    }

    public static bool IsExactSoftwareFirmwareField(string? name)
        => F6201BFieldAssociation.IsExactSoftwareFirmwareField(name);

    private static string Normalize(string value)
        => Regex.Replace(value.Trim(), @"\s+", string.Empty);
}
