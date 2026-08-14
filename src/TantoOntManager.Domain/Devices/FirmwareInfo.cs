namespace TantoOntManager.Domain.Devices;

public sealed record FirmwareInfo(
    string? SoftwareVersion,
    string? HardwareVersion,
    string? BootVersion)
{
    public static FirmwareInfo Unknown { get; } = new(null, null, null);

    public const string PublicMissing = "Não disponível na interface pública";
    public const string AuthenticatedMissing = "Não localizado nas páginas autenticadas homologadas";

    public string SoftwareDisplay => SoftwareVersion ?? PublicMissing;
    public string HardwareDisplay => HardwareVersion ?? PublicMissing;
    public string BootDisplay => BootVersion ?? PublicMissing;

    public static string Display(string? value, bool authenticated)
        => string.IsNullOrWhiteSpace(value)
            ? (authenticated ? AuthenticatedMissing : PublicMissing)
            : value;
}
