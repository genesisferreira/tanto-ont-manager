using System.Net;
using System.Text.RegularExpressions;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BV9310P8N1AuthenticatedPageParser
{
    public static DeviceIdentity ParseIdentity(string manufacturer, string? fallbackModel, params string[] pages)
    {
        var combined = string.Join('\n', pages);
        var software = First(combined, "Software Version", "SoftwareVer", "Frm_SoftwareVer", "SWVer");
        var hardware = First(combined, "Hardware Version", "HardwareVer", "Frm_HardwareVer", "HWVer");
        var boot = First(combined, "Boot Version", "BootVer", "Frm_BootVer", "BootVer");
        var serial = First(combined, "Serial Number", "SerialNumber", "Frm_SerialNumber", "GPON SN", "SN");
        var mac = First(combined, "MAC Address", "MACAddress", "Frm_MACAddress", "MAC");
        var model = First(combined, "Model Name", "ModelName", "Frm_ModelName") ?? fallbackModel;

        return new DeviceIdentity(
            manufacturer,
            model,
            new FirmwareInfo(software, hardware, boot),
            serial,
            mac);
    }

    public static DeviceDiagnostics ParseDiagnostics(params string[] pages)
    {
        var combined = string.Join('\n', pages);
        var pon = First(combined, "ONU State", "OnuState", "PON Status", "PonState", "Frm_PonState");
        var temperature = First(combined, "Temperature", "Frm_Temperature", "OptTemperature");
        var tx = First(combined, "Tx Power", "TxPower", "Frm_TxPower", "OpticalTx");
        var rx = First(combined, "Rx Power", "RxPower", "Frm_RxPower", "OpticalRx");
        var profiles = ParseWanProfiles(combined);

        return new DeviceDiagnostics(
            new PonState(pon, pon is null ? "Estado PON não lido nas páginas GET homologadas." : null),
            new OpticalReading(temperature, tx, rx),
            profiles,
            profiles.Count == 0 ? "Nenhum perfil WAN visível nas páginas GET homologadas." : null,
            false,
            "Leitura autenticada somente GET, firmware F6201B V9.3.10P8N1.");
    }

    public static bool FirmwareMatchesWhenPresent(DeviceIdentity identity)
    {
        var software = identity.Firmware.SoftwareVersion;
        if (string.IsNullOrWhiteSpace(software))
        {
            return true;
        }

        return software.Contains(F6201BV9310P8N1AuthContract.ExpectedSoftware, StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeSessionExpired(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        return body.Contains("login_need_refresh", StringComparison.Ordinal)
               && body.Contains("Please login", StringComparison.OrdinalIgnoreCase)
               && !body.Contains("MenuPage=", StringComparison.Ordinal);
    }

    private static IReadOnlyList<WanProfile> ParseWanProfiles(string text)
    {
        var profiles = new List<WanProfile>();
        var nameMatches = Regex.Matches(
            text,
            @"(?i)(?:WAN(?:\s*Name)?|Frm_WanName|ConnectionName)\s*[:=]\s*[""']?([A-Za-z0-9_\-]+)");
        foreach (Match match in nameMatches)
        {
            var name = match.Groups[1].Value;
            if (profiles.Any(item => item.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            profiles.Add(new WanProfile(
                name,
                FirstNear(text, name, "Type", "LinkType", "ConnectionType"),
                FirstNear(text, name, "Service", "ServiceList"),
                FirstNear(text, name, "LinkType"),
                null,
                null,
                null,
                ParseInt(FirstNear(text, name, "VLAN", "VLAN ID", "VlanId", "VID")),
                null,
                FirstNear(text, name, "Status", "ConnectionStatus", "ConnStatus"),
                null,
                null));
        }

        return profiles;
    }

    private static string? First(string text, params string[] labels)
    {
        foreach (var label in labels)
        {
            var match = Regex.Match(
                text,
                $@"(?i)(?:{Regex.Escape(label)})\s*[:=]\s*[""']?([A-Za-z0-9._+\-]+)");
            if (match.Success)
            {
                return match.Groups[1].Value;
            }

            match = Regex.Match(
                text,
                $@"(?i)<[^>]+(?:name|id)=[""'][^""']*{Regex.Escape(label)}[^""']*[""'][^>]+value=[""']([^""']+)[""']");
            if (match.Success && !string.IsNullOrWhiteSpace(match.Groups[1].Value))
            {
                return match.Groups[1].Value;
            }

            match = Regex.Match(
                text,
                $@"(?i){Regex.Escape(label)}</t[dh]>\s*<t[dh][^>]*>\s*([^<]+)");
            if (match.Success)
            {
                var value = match.Groups[1].Value.Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }
        }

        return null;
    }

    private static string? FirstNear(string text, string name, params string[] labels)
    {
        var window = ExtractWindow(text, name);
        return First(window, labels);
    }

    private static string ExtractWindow(string text, string name)
    {
        var idx = text.IndexOf(name, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return text;
        }

        var start = Math.Max(0, idx - 240);
        var length = Math.Min(text.Length - start, 720);
        return text.Substring(start, length);
    }

    private static int? ParseInt(string? value)
        => int.TryParse(value, out var number) ? number : null;
}
