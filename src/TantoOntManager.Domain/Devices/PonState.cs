namespace TantoOntManager.Domain.Devices;

public sealed record PonState(
    string? OnuState,
    string? Description,
    string? Loid = null,
    string? GponSerial = null)
{
    public static PonState Unknown { get; } = new(null, "Estado PON não disponível na interface pública.");

    public static string FormatOnuState(string? raw, bool authenticated)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return authenticated
                ? FirmwareInfo.AuthenticatedMissing
                : "Estado PON não disponível na interface pública.";
        }

        var value = raw.Trim();
        if (value is "-1" or "−1")
        {
            return "Desconhecido (-1)";
        }

        return value;
    }
}

public sealed record OpticalReading(
    string? Temperature,
    string? TxPower,
    string? RxPower,
    string? Voltage = null,
    string? BiasCurrent = null)
{
    public static OpticalReading Unavailable { get; } = new(null, null, null);
}
