namespace TantoOntManager.Domain.Devices;

public sealed record DeviceIdentity(
    string Manufacturer,
    string? Model,
    FirmwareInfo Firmware,
    string? SerialNumber,
    string? MacAddress)
{
    public bool HasConfirmedModel => !string.IsNullOrWhiteSpace(Model);
}
