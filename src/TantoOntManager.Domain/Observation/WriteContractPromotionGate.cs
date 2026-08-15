using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;

namespace TantoOntManager.Domain.Observation;

public static class WriteContractPromotionGate
{
    public static Result Evaluate(ObservationSnapshot? snapshot)
    {
        var candidate = snapshot?.WriteCandidate;
        var capability = snapshot?.WriteCapability;
        if (snapshot is null || candidate is null || snapshot.Counters.WriteCandidatesIntercepted == 0)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WritePromotionBlocked,
                "Promoção recusada: candidatos interceptados = 0."));
        }

        if (capability is null || capability.Firmware != FirmwareCompatibility.ConfirmedCompatible)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WritePromotionBlocked,
                "Promoção recusada: firmware não confirmada."));
        }

        if (capability.PppoeAvailable != WriteCapabilityAvailability.Available)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WritePromotionBlocked,
                "Promoção recusada: PPPoE não está disponível nesta conta/firmware."));
        }

        if (capability.ApplySaveAvailable != WriteCapabilityAvailability.Available)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WritePromotionBlocked,
                "Promoção recusada: Apply/Save não está disponível."));
        }

        if (capability.Conclusion is WriteCapabilityConclusion.ReadOnlyAccount
            or WriteCapabilityConclusion.PresetLocked
            or WriteCapabilityConclusion.PppoeOptionUnavailable
            or WriteCapabilityConclusion.InsufficientEvidence)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WritePromotionBlocked,
                "Promoção recusada: a conta/firmware não expõe escrita PPPoE homologável (" + capability.Conclusion + ")."));
        }

        if (capability.Conclusion != WriteCapabilityConclusion.WriteUiAvailable)
        {
            return Result.Failure(Error.Create(
                ErrorCodes.WritePromotionBlocked,
                "Promoção recusada: conclusão de capacidade insuficiente."));
        }

        return Result.Success();
    }
}
