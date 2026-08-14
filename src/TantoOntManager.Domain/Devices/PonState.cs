namespace TantoOntManager.Domain.Devices;

public sealed record PonState(
    string? OnuState,
    string? Description)
{
    public static PonState Unknown { get; } = new(null, "Estado PON não disponível na interface pública.");
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
