using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;

namespace TantoOntManager.Domain.Observation;

public static class WriteCaptureEligibility
{
    public const string ConfirmationPhrase = "MAPEAR F6201B";
    public const string ExpectedSoftware = "V9.3.10P8N1";

    public static Result Evaluate(WriteCaptureEligibilityInput input)
    {
        if (!input.Authenticated)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.ObservationRequiresSession,
                "A captura bloqueada exige sessão autenticada ativa."));
        }

        if (!string.Equals(input.Manufacturer, ManufacturerNames.Zte, StringComparison.OrdinalIgnoreCase))
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WriteCaptureModelRejected,
                "A captura bloqueada exige fabricante ZTE confirmado."));
        }

        var model = input.Model ?? string.Empty;
        if (model.IndexOf("F6201B", StringComparison.OrdinalIgnoreCase) < 0)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WriteCaptureModelRejected,
                "A captura bloqueada exige modelo F6201B confirmado."));
        }

        if (input.Firmware == FirmwareCompatibility.Unconfirmed)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WriteCaptureFirmwareUnconfirmed,
                "Firmware Unconfirmed: a captura de gravação permanece recusada; somente leitura continua permitida."));
        }

        if (input.Firmware == FirmwareCompatibility.ConfirmedIncompatible)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WriteCaptureFirmwareIncompatible,
                "Firmware incompatível: a captura de gravação foi recusada."));
        }

        if (input.Firmware != FirmwareCompatibility.ConfirmedCompatible
            || !string.Equals(input.SoftwareVersion, ExpectedSoftware, StringComparison.Ordinal))
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WriteCaptureFirmwareUnconfirmed,
                "A captura bloqueada exige Software Version exatamente V9.3.10P8N1."));
        }

        if (!IsExactConfirmation(input.Confirmation))
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WriteCaptureConfirmationRejected,
                "Digite exatamente MAPEAR F6201B para iniciar a captura bloqueada."));
        }

        return Result.Success();
    }

    public static bool IsExactConfirmation(string? confirmation)
        => confirmation == ConfirmationPhrase;

    public static bool AllowsNetwork(ObservationDecision decision)
        => decision.Allowed;

    public static WriteCaptureEligibilityInput CompatibleLab(string? confirmation)
        => new(
            ManufacturerNames.Zte,
            DeviceModelIds.ZteF6201B,
            FirmwareCompatibility.ConfirmedCompatible,
            ExpectedSoftware,
            true,
            confirmation);
}
