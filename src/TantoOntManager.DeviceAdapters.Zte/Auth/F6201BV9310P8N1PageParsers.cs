using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Diagnostics;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record F6201BParsedDeviceInformation(
    string? DeviceType,
    string? HardwareVersion,
    string? SoftwareVersion,
    string? BootVersion,
    string? SerialNumber,
    string? MacAddress,
    IReadOnlyList<FieldEvidence> Evidence,
    bool Partial);

public sealed record F6201BParsedPonStatus(
    string? OnuState,
    string? Temperature,
    string? InputPower,
    string? OutputPower,
    string? Voltage,
    string? BiasCurrent,
    IReadOnlyList<FieldEvidence> Evidence,
    bool Partial);

public sealed record F6201BParsedWanSummary(
    IReadOnlyList<WanProfile> Profiles,
    IReadOnlyList<FieldEvidence> Evidence,
    bool Partial,
    string? Note);

public static class F6201BV9310P8N1DeviceInformationParser
{
    public static F6201BParsedDeviceInformation Parse(params (string Page, string Body)[] pages)
    {
        var evidence = new List<FieldEvidence>();
        string? Read(string field, params string[] keys)
        {
            foreach (var page in pages)
            {
                var parsed = F6201BLabeledValueReader.Read(page.Page, page.Body, keys);
                if (parsed.Found)
                {
                    evidence.Add(parsed.Evidence!);
                    return parsed.Value;
                }
            }

            return null;
        }

        var deviceType = Read("DeviceType", "Device Type", "DeviceType", "ModelName", "Model Name", "Frm_ModelName");
        var hardware = Read("HardwareVersion", "Hardware Version", "HardwareVer", "HwVer", "Frm_HardwareVer", "HWVer");
        var software = Read("SoftwareVersion", "Software Version", "SoftwareVer", "SwVer", "Frm_SoftwareVer", "SWVer");
        var boot = Read("BootVersion", "Boot Version", "BootVer", "Frm_BootVer");
        var serial = Read("SerialNumber", "Serial Number", "SerialNum", "SerialNumber", "Frm_SerialNumber", "GPON SN", "GPONSN");
        var mac = Read("MacAddress", "MAC Address", "MacAddr", "MACAddress", "Frm_MACAddress");

        var found = new[] { deviceType, hardware, software, boot, serial, mac }.Count(value => !string.IsNullOrWhiteSpace(value));
        return new F6201BParsedDeviceInformation(
            deviceType,
            hardware,
            software,
            boot,
            serial,
            mac,
            evidence,
            found is > 0 and < 6);
    }
}

public static class F6201BV9310P8N1PonParser
{
    public static F6201BParsedPonStatus Parse(params (string Page, string Body)[] pages)
    {
        var evidence = new List<FieldEvidence>();
        string? Read(params string[] keys)
        {
            foreach (var page in pages)
            {
                var parsed = F6201BLabeledValueReader.Read(page.Page, page.Body, keys);
                if (parsed.Found)
                {
                    evidence.Add(parsed.Evidence!);
                    return parsed.Value;
                }
            }

            return null;
        }

        var onu = Read("ONU State", "OnuState", "PonState", "PON Status", "Frm_PonState", "ONUState");
        var temperature = Read("Temperature", "Frm_Temperature", "OptTemperature", "OpticTemperature");
        var input = Read("Optical Module Input Power", "RxPower", "Frm_RxPower", "OpticalRx", "InputPower");
        var output = Read("Optical Module Output Power", "TxPower", "Frm_TxPower", "OpticalTx", "OutputPower");
        var voltage = Read("Supply Voltage", "Voltage", "Frm_Voltage", "SupplyVoltage");
        var bias = Read("Transmitter Bias Current", "BiasCurrent", "Bias", "Frm_Bias", "TxBias");

        var found = new[] { onu, temperature, input, output, voltage, bias }.Count(value => !string.IsNullOrWhiteSpace(value));
        return new F6201BParsedPonStatus(
            onu,
            temperature,
            input,
            output,
            voltage,
            bias,
            evidence,
            found is > 0 and < 6);
    }
}

public static class F6201BV9310P8N1WanParser
{
    public static F6201BParsedWanSummary Parse(params (string Page, string Body)[] pages)
    {
        var evidence = new List<FieldEvidence>();
        var profiles = new List<WanProfile>();

        foreach (var page in pages)
        {
            foreach (var obj in F6201BLabeledValueReader.ReadJsonObjectArrays(page.Body))
            {
                var name = First(obj, "WANCName", "ViewName", "Name", "WanName", "ConnectionName");
                if (string.IsNullOrWhiteSpace(name) || !LooksLikeWanObject(obj))
                {
                    continue;
                }

                Add(profiles, evidence, page.Page, name, obj);
            }

            AddFromHtmlTable(page.Page, page.Body, profiles, evidence);
        }

        return new F6201BParsedWanSummary(
            profiles,
            evidence,
            profiles.Count > 0,
            profiles.Count == 0 ? "Nenhum perfil WAN visível nas páginas GET homologadas." : null);
    }

    private static void Add(
        List<WanProfile> profiles,
        List<FieldEvidence> evidence,
        string page,
        string name,
        IReadOnlyDictionary<string, string> obj)
    {
        if (profiles.Any(item => item.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        var ip = First(obj, "IPAddress", "ExternalIPAddress", "Ipv4Address");
        var mac = First(obj, "MACAddress", "MacAddr", "WorkIFMac");
        profiles.Add(new WanProfile(
            name,
            First(obj, "ConnType", "WANCType", "Type", "ConnectionType"),
            First(obj, "ServList", "ServiceList", "Service"),
            First(obj, "LinkType"),
            First(obj, "IPType", "AddressingType", "AddressType"),
            First(obj, "IPVersion", "IPMode", "IpVer"),
            F6201BLabeledValueReader.ParseBool(First(obj, "NATEnabled", "NAT", "EnableNAT")),
            F6201BLabeledValueReader.ParseInt(First(obj, "VLANID", "VLAN", "VID", "VLANIDMark")),
            F6201BLabeledValueReader.ParseInt(First(obj, "Priority", "Priority8021", "8021p", "VlanPriority")),
            First(obj, "ConnStatus", "Status", "ConnectionStatus"),
            First(obj, "DisconnectReason", "ConnError"),
            SensitiveDataMasker.MaskIpv4(ip)));

        evidence.Add(new FieldEvidence("WanName", name, page, "json-wan", name));
        if (!string.IsNullOrWhiteSpace(mac))
        {
            evidence.Add(new FieldEvidence("WanMac", SensitiveDataMasker.MaskMac(mac), page, "json-wan", "MAC mascarado"));
        }
    }

    private static void AddFromHtmlTable(
        string page,
        string html,
        List<WanProfile> profiles,
        List<FieldEvidence> evidence)
    {
        var decoded = F6201BHtmlText.Decode(html);
        foreach (var candidate in new[] { "HSI_TR069", "VOIP_IPTV" })
        {
            if (!decoded.Contains(candidate, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (profiles.Any(item => item.Name.Equals(candidate, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var windowStart = decoded.IndexOf(candidate, StringComparison.OrdinalIgnoreCase);
            var window = decoded.Substring(Math.Max(0, windowStart - 80), Math.Min(decoded.Length - Math.Max(0, windowStart - 80), 900));
            var vlan = F6201BLabeledValueReader.Read(page, window, "VLAN", "VLAN ID", "VLANID", "VID");
            var status = F6201BLabeledValueReader.Read(page, window, "Status", "ConnectionStatus", "ConnStatus");
            var service = F6201BLabeledValueReader.Read(page, window, "Service List", "ServiceList", "ServList", "Service");
            var type = F6201BLabeledValueReader.Read(page, window, "Type", "Link Type", "LinkType", "ConnType");
            profiles.Add(new WanProfile(
                candidate,
                type.Value,
                service.Value,
                type.Value,
                null,
                null,
                null,
                F6201BLabeledValueReader.ParseInt(vlan.Value),
                null,
                status.Value,
                null,
                null));
            evidence.Add(new FieldEvidence("WanName", candidate, page, "html-table", candidate));
        }
    }

    private static bool LooksLikeWanObject(IReadOnlyDictionary<string, string> obj)
        => obj.Keys.Any(key =>
            key.Contains("WAN", StringComparison.OrdinalIgnoreCase)
            || key.Contains("VLAN", StringComparison.OrdinalIgnoreCase)
            || key.Contains("ServList", StringComparison.OrdinalIgnoreCase)
            || key.Contains("ConnType", StringComparison.OrdinalIgnoreCase)
            || key.Contains("ConnStatus", StringComparison.OrdinalIgnoreCase));

    private static string? First(IReadOnlyDictionary<string, string> obj, params string[] keys)
    {
        foreach (var key in keys)
        {
            foreach (var pair in obj)
            {
                if (pair.Key.Equals(key, StringComparison.OrdinalIgnoreCase)
                    && !F6201BLabeledValueReader.IsSecretKey(pair.Key)
                    && !string.IsNullOrWhiteSpace(pair.Value))
                {
                    return pair.Value.Trim();
                }
            }
        }

        return null;
    }
}

public static class F6201BV9310P8N1AuthenticatedPageParser
{
    public static DeviceIdentity ToIdentity(
        string manufacturer,
        string? fallbackModel,
        F6201BParsedDeviceInformation parsed)
        => new(
            manufacturer,
            parsed.DeviceType ?? fallbackModel,
            new FirmwareInfo(parsed.SoftwareVersion, parsed.HardwareVersion, parsed.BootVersion),
            parsed.SerialNumber,
            parsed.MacAddress);

    public static DeviceDiagnostics ToDiagnostics(
        F6201BParsedPonStatus pon,
        F6201BParsedWanSummary wan)
        => new(
            new PonState(pon.OnuState, pon.OnuState is null ? "Estado PON não lido nas páginas GET homologadas." : null),
            new OpticalReading(pon.Temperature, pon.OutputPower, pon.InputPower, pon.Voltage, pon.BiasCurrent),
            wan.Profiles,
            wan.Note,
            false,
            "Leitura autenticada somente GET, firmware F6201B V9.3.10P8N1.");

    public static bool FirmwareMatchesWhenPresent(DeviceIdentity identity)
    {
        var software = identity.Firmware.SoftwareVersion;
        if (string.IsNullOrWhiteSpace(software))
        {
            return true;
        }

        return software.Contains(F6201BV9310P8N1AuthContract.ExpectedSoftware, StringComparison.OrdinalIgnoreCase);
    }
}
