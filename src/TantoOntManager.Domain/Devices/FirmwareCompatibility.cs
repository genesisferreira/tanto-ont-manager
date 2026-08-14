namespace TantoOntManager.Domain.Devices;

public enum FirmwareCompatibility
{
    Unconfirmed = 0,
    ConfirmedCompatible = 1,
    ConfirmedIncompatible = 2
}

public static class FirmwareCompatibilityDisplay
{
    public const string AuthenticatedUnconfirmed =
        "Autenticado — somente leitura; firmware ainda não confirmada";

    public const string AuthenticatedCompatible = "Autenticado — somente leitura";

    public static string ToAuthenticatedUiLabel(this FirmwareCompatibility compatibility)
        => compatibility == FirmwareCompatibility.Unconfirmed
            ? AuthenticatedUnconfirmed
            : AuthenticatedCompatible;
}
