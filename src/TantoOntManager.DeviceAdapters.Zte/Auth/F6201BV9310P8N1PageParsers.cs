using System.Text.RegularExpressions;
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
    bool Partial,
    string? Loid = null,
    string? GponSerial = null);

public sealed record F6201BParsedWanSummary(
    IReadOnlyList<WanProfile> Profiles,
    IReadOnlyList<FieldEvidence> Evidence,
    bool Partial,
    string? Note);

public static class F6201BV9310P8N1DeviceInformationParser
{
    public static F6201BParsedDeviceInformation Parse(params (string Page, string Body)[] pages)
    {
        var source = pages
            .Where(page => F6201BFirmwareCompatibility.LooksLikeDeviceInformationPage(page.Page, page.Body))
            .ToArray();
        if (source.Length == 0)
        {
            return new F6201BParsedDeviceInformation(null, null, null, null, null, null, [], false);
        }

        var evidence = new List<FieldEvidence>();
        string? ReadExact(string[] xmlObjects, params string[] keys)
        {
            foreach (var page in source)
            {
                if (xmlObjects.Length > 0
                    && page.Body.IndexOf("ParaName", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    foreach (var xmlObject in xmlObjects)
                    {
                        var parsed = F6201BLabeledValueReader.ReadExactFromObject(page.Page, page.Body, xmlObject, keys);
                        if (parsed.Found)
                        {
                            evidence.Add(parsed.Evidence!);
                            return parsed.Value;
                        }
                    }

                    continue;
                }

                var fallback = F6201BLabeledValueReader.ReadExact(page.Page, page.Body, keys);
                if (fallback.Found && F6201BFieldAssociation.IsUsableScalar(fallback.Value))
                {
                    evidence.Add(fallback.Evidence!);
                    return fallback.Value;
                }
            }

            return null;
        }

        var deviceType = ReadExact(F6201BV9310P8N1XmlFieldAliases.DeviceObjects, F6201BV9310P8N1XmlFieldAliases.DeviceType);
        var hardware = ReadExact(F6201BV9310P8N1XmlFieldAliases.DeviceObjects, F6201BV9310P8N1XmlFieldAliases.HardwareVersion);
        var software = ReadExact(F6201BV9310P8N1XmlFieldAliases.DeviceObjects, F6201BV9310P8N1XmlFieldAliases.SoftwareVersion);
        var boot = ReadExact(F6201BV9310P8N1XmlFieldAliases.DeviceObjects, F6201BV9310P8N1XmlFieldAliases.BootVersion);
        var serial = ReadExact(F6201BV9310P8N1XmlFieldAliases.DeviceObjects, F6201BV9310P8N1XmlFieldAliases.SerialNumber);
        var mac = ReadExact(F6201BV9310P8N1XmlFieldAliases.DeviceObjects, F6201BV9310P8N1XmlFieldAliases.DeviceMac);

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
        var source = pages.Where(page => LooksLikePonPage(page.Page, page.Body)).ToArray();
        var evidence = new List<FieldEvidence>();
        string? ReadExact(string[] xmlObjects, params string[] keys)
        {
            foreach (var page in source)
            {
                if (xmlObjects.Length > 0
                    && page.Body.IndexOf("ParaName", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    foreach (var xmlObject in xmlObjects)
                    {
                        var parsed = F6201BLabeledValueReader.ReadExactFromObject(page.Page, page.Body, xmlObject, keys);
                        if (parsed.Found)
                        {
                            evidence.Add(parsed.Evidence!);
                            return parsed.Value;
                        }
                    }

                    continue;
                }

                var fallback = F6201BLabeledValueReader.ReadExact(page.Page, page.Body, keys);
                if (fallback.Found && F6201BFieldAssociation.IsUsableScalar(fallback.Value))
                {
                    evidence.Add(fallback.Evidence!);
                    return fallback.Value;
                }
            }

            return null;
        }

        var onu = ReadExact(
            F6201BV9310P8N1XmlFieldAliases.OnuStateObjects,
            F6201BV9310P8N1XmlFieldAliases.OnuStateInRegistrationObject);
        var temperature = ReadExact(
            F6201BV9310P8N1XmlFieldAliases.OpticalObjects,
            F6201BV9310P8N1XmlFieldAliases.Temperature);
        var input = ReadExact(
            F6201BV9310P8N1XmlFieldAliases.OpticalObjects,
            F6201BV9310P8N1XmlFieldAliases.InputPower);
        var output = ReadExact(
            F6201BV9310P8N1XmlFieldAliases.OpticalObjects,
            F6201BV9310P8N1XmlFieldAliases.OutputPower);
        var voltage = ReadExact(
            F6201BV9310P8N1XmlFieldAliases.OpticalObjects,
            F6201BV9310P8N1XmlFieldAliases.Voltage);
        var bias = ReadExact(
            F6201BV9310P8N1XmlFieldAliases.OpticalObjects,
            F6201BV9310P8N1XmlFieldAliases.Bias);
        var loid = ReadExact(
            F6201BV9310P8N1XmlFieldAliases.LoidObjects,
            F6201BV9310P8N1XmlFieldAliases.Loid);
        var gponSn = ReadExact(
            F6201BV9310P8N1XmlFieldAliases.GponSnObjects,
            F6201BV9310P8N1XmlFieldAliases.GponSn);

        var found = new[] { onu, temperature, input, output, voltage, bias, loid, gponSn }.Count(value => !string.IsNullOrWhiteSpace(value));
        return new F6201BParsedPonStatus(
            onu,
            temperature,
            input,
            output,
            voltage,
            bias,
            evidence,
            found is > 0 and < 8,
            loid,
            gponSn);
    }

    private static bool LooksLikePonPage(string page, string body)
    {
        if (page.Contains("pon", StringComparison.OrdinalIgnoreCase)
            || page.Contains("optical", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var compact = F6201BFieldAssociation.Compact(body);
        return compact.Contains("ONUSTATE")
               || compact.Contains("FRMPONSTATE")
               || compact.Contains("OPTICALMODULEINPUTPOWER")
               || compact.Contains("FRMRXPOWER")
               || compact.Contains("PONLOID")
               || compact.Contains("OBJGPONREGSTATUSID")
               || compact.Contains("OBJPONOPTICALPARAID")
               || compact.Contains("OBJUPLINKCONFID")
               || compact.Contains("OBJSNINFOID");
    }
}

public static class F6201BV9310P8N1WanParser
{
    public static F6201BParsedWanSummary Parse(params (string Page, string Body)[] pages)
    {
        var evidence = new List<FieldEvidence>();
        var profiles = new List<WanProfile>();

        foreach (var page in pages.Where(item => LooksLikeWanPage(item.Page, item.Body)))
        {
            foreach (var obj in F6201BLabeledValueReader.ReadXmlInstances(page.Body)
                         .Concat(F6201BLabeledValueReader.ReadJsonObjectArrays(page.Body)))
            {
                var name = First(obj, "WANCName", "ViewName", "ConnectionName", "WanName", "Name");
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
        var ip = First(obj, "IPAddress", "ExternalIPAddress", "Ipv4Address");
        var mac = First(obj, "MACAddress", "MacAddr", "WorkIFMac");
        var user = First(obj, "Username", "PPPUsername", "PPPoEUser");
        var dns = First(obj, "DNS1", "DNSAddress", "Dns");
        var gateway = First(obj, "GateWay", "Gateway", "DefaultGateway");
        var created = new WanProfile(
            name,
            First(obj, "ConnType", "WANCType", "ConnectionType", "Type"),
            First(obj, "ServList", "ServiceList"),
            First(obj, "LinkType"),
            First(obj, "IPType", "AddressingType", "AddressType", "IPv4 Type"),
            First(obj, "IPVersion", "IPMode", "IpVer"),
            F6201BLabeledValueReader.ParseBool(First(obj, "NATEnabled", "EnableNAT", "NAT")),
            F6201BLabeledValueReader.ParseInt(First(obj, "VLANID", "VLANIDMark", "VID", "VLAN ID")),
            F6201BLabeledValueReader.ParseInt(First(obj, "Priority", "Priority8021", "VlanPriority", "802.1p")),
            First(obj, "ConnStatus", "ConnectionStatus", "Status"),
            First(obj, "DisconnectReason", "ConnError"),
            string.IsNullOrWhiteSpace(ip) ? null : SensitiveDataMasker.MaskIpv4(ip),
            string.IsNullOrWhiteSpace(mac) ? null : SensitiveDataMasker.MaskMac(mac),
            string.IsNullOrWhiteSpace(user) ? null : SensitiveDataMasker.MaskUsername(user),
            F6201BLabeledValueReader.ParseBool(First(obj, "VLANEnabled", "EnableVLAN", "VLANMode", "VLAN")),
            First(obj, "MTU"),
            string.IsNullOrWhiteSpace(dns) ? null : SensitiveDataMasker.MaskIpv4(dns),
            string.IsNullOrWhiteSpace(gateway) ? null : SensitiveDataMasker.MaskIpv4(gateway),
            First(obj, "ConnDuration", "Duration", "UpTime"));

        var existing = profiles.FindIndex(item => item.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (existing >= 0)
        {
            profiles[existing] = Merge(profiles[existing], created);
        }
        else
        {
            profiles.Add(created);
        }

        evidence.Add(new FieldEvidence("WanName", name, page, "xml-wan", name));
        if (!string.IsNullOrWhiteSpace(mac))
        {
            evidence.Add(new FieldEvidence("WanMac", SensitiveDataMasker.MaskMac(mac), page, "xml-wan", "MAC mascarado"));
        }
    }

    private static WanProfile Merge(WanProfile left, WanProfile right)
        => left with
        {
            Mode = left.Mode ?? right.Mode,
            ServiceList = left.ServiceList ?? right.ServiceList,
            LinkType = left.LinkType ?? right.LinkType,
            IpType = left.IpType ?? right.IpType,
            AddressFamily = left.AddressFamily ?? right.AddressFamily,
            NatEnabled = left.NatEnabled ?? right.NatEnabled,
            VlanId = left.VlanId ?? right.VlanId,
            Priority8021p = left.Priority8021p ?? right.Priority8021p,
            ConnectionState = left.ConnectionState ?? right.ConnectionState,
            DisconnectReason = left.DisconnectReason ?? right.DisconnectReason,
            Ipv4Address = left.Ipv4Address ?? right.Ipv4Address,
            MacAddress = left.MacAddress ?? right.MacAddress,
            PppoeUsername = left.PppoeUsername ?? right.PppoeUsername,
            VlanEnabled = left.VlanEnabled ?? right.VlanEnabled,
            Mtu = left.Mtu ?? right.Mtu,
            Dns = left.Dns ?? right.Dns,
            Gateway = left.Gateway ?? right.Gateway,
            Duration = left.Duration ?? right.Duration
        };

    private static void AddFromHtmlTable(
        string page,
        string html,
        List<WanProfile> profiles,
        List<FieldEvidence> evidence)
    {
        var decoded = F6201BHtmlText.Decode(html);
        var tables = Regex.Split(decoded, "(?i)</table>");
        foreach (var table in tables)
        {
            var rows = Regex.Split(table, "(?i)</tr>")
                .Select(row => Regex.Matches(row, "(?is)<t[dh][^>]*>(.*?)</t[dh]>")
                    .Select(match => F6201BHtmlText.Normalize(Regex.Replace(match.Groups[1].Value, "(?is)<[^>]+>", " ")))
                    .ToList())
                .Where(cells => cells.Count > 0)
                .ToList();
            if (rows.Count < 2)
            {
                continue;
            }

            var headers = rows[0];
            var nameIndex = IndexOfHeader(headers, "Connection Name", "WANCName", "Name", "WanName");
            if (nameIndex < 0)
            {
                continue;
            }

            for (var i = 1; i < rows.Count; i++)
            {
                var cells = rows[i];
                if (nameIndex >= cells.Count)
                {
                    continue;
                }

                var name = cells[nameIndex];
                if (!F6201BFieldAssociation.IsUsableScalar(name)
                    || profiles.Any(item => item.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                profiles.Add(new WanProfile(
                    name,
                    Cell(headers, cells, "Type", "ConnType", "ConnectionType"),
                    Cell(headers, cells, "Service List", "ServList", "ServiceList"),
                    Cell(headers, cells, "Link Type", "LinkType"),
                    Cell(headers, cells, "IPv4 Type", "IPType"),
                    Cell(headers, cells, "IP Version", "IPVersion"),
                    F6201BLabeledValueReader.ParseBool(Cell(headers, cells, "NAT", "NATEnabled")),
                    F6201BLabeledValueReader.ParseInt(Cell(headers, cells, "VLAN ID", "VLANID", "VID")),
                    F6201BLabeledValueReader.ParseInt(Cell(headers, cells, "802.1p", "Priority")),
                    Cell(headers, cells, "IPv4 Status", "ConnStatus", "Status"),
                    Cell(headers, cells, "Disconnect Reason", "DisconnectReason"),
                    MaskIf(Cell(headers, cells, "IP Address", "IPAddress"), SensitiveDataMasker.MaskIpv4),
                    MaskIf(Cell(headers, cells, "MAC Address", "MACAddress"), SensitiveDataMasker.MaskMac),
                    MaskIf(Cell(headers, cells, "PPPoE Username", "Username"), SensitiveDataMasker.MaskUsername),
                    F6201BLabeledValueReader.ParseBool(Cell(headers, cells, "VLAN", "VLANEnabled"))));
                evidence.Add(new FieldEvidence("WanName", name, page, "html-table-row", name));
            }
        }
    }

    private static int IndexOfHeader(IReadOnlyList<string> headers, params string[] names)
    {
        for (var i = 0; i < headers.Count; i++)
        {
            if (names.Any(name => F6201BFieldAssociation.NamesEqual(headers[i], name)))
            {
                return i;
            }
        }

        return -1;
    }

    private static string? Cell(IReadOnlyList<string> headers, IReadOnlyList<string> cells, params string[] names)
    {
        var index = IndexOfHeader(headers, names);
        if (index < 0 || index >= cells.Count)
        {
            return null;
        }

        var value = cells[index];
        return F6201BFieldAssociation.IsUsableScalar(value) ? value : null;
    }

    private static string? MaskIf(string? value, Func<string?, string> mask)
        => string.IsNullOrWhiteSpace(value) ? null : mask(value);

    private static bool LooksLikeWanPage(string page, string body)
        => page.Contains("wan", StringComparison.OrdinalIgnoreCase)
           || page.Contains("ethWan", StringComparison.OrdinalIgnoreCase)
           || body.Contains("OBJ_WANIP", StringComparison.OrdinalIgnoreCase)
           || body.Contains("ID_WAN_COMFIG", StringComparison.OrdinalIgnoreCase)
           || body.Contains("WANCName", StringComparison.OrdinalIgnoreCase);

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
                if (F6201BFieldAssociation.NamesEqual(pair.Key, key)
                    && !F6201BLabeledValueReader.IsPasswordKey(pair.Key)
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
            new PonState(
                pon.OnuState,
                pon.OnuState is null
                    ? FirmwareInfo.AuthenticatedMissing
                    : PonState.FormatOnuState(pon.OnuState, true),
                pon.Loid,
                pon.GponSerial),
            new OpticalReading(pon.Temperature, pon.OutputPower, pon.InputPower, pon.Voltage, pon.BiasCurrent),
            wan.Profiles,
            wan.Note,
            false,
            "Leitura autenticada somente GET, firmware F6201B V9.3.10P8N1.");

    public static FirmwareCompatibility ClassifyFirmware(DeviceIdentity identity)
        => F6201BFirmwareCompatibility.Classify(identity);

    public static bool FirmwareMatchesWhenPresent(DeviceIdentity identity)
        => F6201BFirmwareCompatibility.Classify(identity) != FirmwareCompatibility.ConfirmedIncompatible;
}
