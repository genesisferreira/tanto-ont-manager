namespace TantoOntManager.Domain.Devices;

public sealed record DeviceCapabilities(
    bool PublicWebInterfaceDetected,
    bool HttpsAvailable,
    bool HttpAvailable,
    bool LoginFormVisible,
    bool AuthenticationMapped,
    bool IdentityReadableWithoutLogin,
    bool DiagnosticsReadableWithoutLogin,
    bool WriteOperationsSupportedByAdapter,
    IReadOnlyList<string> Notes)
{
    public static DeviceCapabilities Empty { get; } = new(
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        ["Nenhuma capacidade confirmada nesta fase."]);
}
