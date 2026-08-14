namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BV9310P8N1XmlFieldAliases
{
    public const string FirmwareFamily = "F6201B-V9.3.10P8N1";

    public static readonly string[] DeviceType =
        ["Device Type", "DeviceType", "ModelName", "Model Name", "Frm_ModelName"];

    public static readonly string[] HardwareVersion =
        ["Hardware Version", "HardwareVersion", "HardwareVer", "HwVer", "Frm_HardwareVer", "HWVer"];

    public static readonly string[] SoftwareVersion =
        ["Software Version", "SoftwareVersion", "SoftwareVer", "Frm_SoftwareVer", "Firmware Version", "FirmwareVersion"];

    public static readonly string[] BootVersion =
        ["Boot Version", "BootVersion", "BootVer", "Frm_BootVer"];

    public static readonly string[] SerialNumber =
        ["Serial Number", "SerialNum", "SerialNumber", "Frm_SerialNumber"];

    public static readonly string[] DeviceMac =
        ["MAC Address", "MacAddr", "MACAddress", "Frm_MACAddress", "WorkIfMac", "WorkIFMac", "BaseMacAddr"];

    public static readonly string[] OnuState =
        ["ONU State", "OnuState", "PonState", "PON Status", "Frm_PonState", "ONUState", "RegStatus", "GponRegStatus"];

    public static readonly string[] OnuStateInRegistrationObject =
        [..OnuState, "Status"];

    public static readonly string[] InputPower =
        ["Input Power", "Optical Module Input Power", "RxPower", "Frm_RxPower", "OpticalRx", "InputPower", "RX optical power"];

    public static readonly string[] OutputPower =
        ["Output Power", "Optical Module Output Power", "TxPower", "Frm_TxPower", "OpticalTx", "OutputPower", "TX optical power"];

    public static readonly string[] Voltage =
        ["Supply Voltage", "Frm_Voltage", "SupplyVoltage", "Voltage"];

    public static readonly string[] Bias =
        ["Transmitter Bias Current", "BiasCurrent", "Frm_Bias", "TxBias", "Bias"];

    public static readonly string[] Temperature =
        ["Temperature", "Frm_Temperature", "OptTemperature", "OpticTemperature"];

    public static readonly string[] Loid =
        ["LOID", "Loid", "PonLoid", "Frm_LOID"];

    public static readonly string[] GponSn =
        ["GPON SN", "GPONSN", "PonSN", "GponSN", "Frm_PonSN"];

    public static readonly string[] DeviceObjects = ["OBJ_DEVINFO_ID", "OBJ_SN_INFO_ID"];

    public static readonly string[] OpticalObjects = ["OBJ_PON_OPTICALPARA_ID"];

    public static readonly string[] OnuStateObjects = ["OBJ_GPONREGSTATUS_ID"];

    public static readonly string[] LoidObjects = ["OBJ_UPLINK_CONF_ID", "OBJ_PON_OPTICALPARA_ID"];

    public static readonly string[] GponSnObjects = ["OBJ_SN_INFO_ID"];

    public static string[] ForUiField(string uiField)
        => uiField switch
        {
            "Device Type" => DeviceType,
            "Hardware Version" => HardwareVersion,
            "Software Version" => SoftwareVersion,
            "Boot Version" => BootVersion,
            "Serial Number" => SerialNumber,
            "MAC Address" => DeviceMac,
            "ONU State" => OnuState,
            "Input Power" => InputPower,
            "Output Power" => OutputPower,
            "Supply Voltage" => Voltage,
            "Transmitter Bias Current" => Bias,
            "Temperature" => Temperature,
            "LOID" => Loid,
            "GPON SN" => GponSn,
            _ => [uiField]
        };

    public static bool KeyMatchesUiField(string xmlKey, string uiField)
        => ForUiField(uiField).Any(alias => F6201BFieldAssociation.NamesEqual(xmlKey, alias));
}
