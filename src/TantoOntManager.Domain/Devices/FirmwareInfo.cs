namespace TantoOntManager.Domain.Devices;

public sealed record FirmwareInfo(
    string? SoftwareVersion,
    string? HardwareVersion,
    string? BootVersion)
{
    public static FirmwareInfo Unknown { get; } = new(null, null, null);

    public string SoftwareDisplay => SoftwareVersion ?? "Não disponível na interface pública";
    public string HardwareDisplay => HardwareVersion ?? "Não disponível na interface pública";
    public string BootDisplay => BootVersion ?? "Não disponível na interface pública";
}
