using System.Text;

namespace TantoOntManager.Domain.Observation;

public static class WriteContractProposalBuilder
{
    public static WriteContractProposalDocument FromCandidate(WriteContractCandidate candidate)
        => new(
            "CandidateOnly",
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            candidate);

    public static string ToSummaryText(WriteContractCandidate candidate)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Proposta de contrato de gravação — somente candidato bloqueado");
        builder.AppendLine("Status: CandidateOnly");
        builder.AppendLine("NetworkRequestSent: false");
        builder.AppendLine("HumanReviewRequired: true");
        builder.AppendLine("BackupContractRequired: true");
        builder.AppendLine("RollbackContractRequired: true");
        builder.AppendLine("Phase2BRequired: true");
        builder.AppendLine("ConfigurationRequestsSent: 0");
        builder.AppendLine("RequestBlockedBeforeNetwork: true");
        builder.AppendLine("Método: " + candidate.Method);
        builder.AppendLine("Endpoint sanitizado: " + candidate.PathSanitized);
        builder.AppendLine("Campos: " + candidate.FieldCount);
        builder.AppendLine("Campos sensíveis redigidos: " + candidate.SensitiveFieldCount);
        builder.AppendLine("Ação: " + (candidate.ActionName ?? "—"));
        builder.AppendLine("Hash da estrutura: " + candidate.StructureSha256);
        builder.AppendLine("Motivo do bloqueio: " + candidate.BlockReason);
        builder.AppendLine("Esta proposta não homologa escrita e não envia configuração.");
        return ObservationSanitizer.SanitizeText(builder.ToString());
    }

    public static string OperatorCounters(ObservationCounters counters, WriteContractCandidate? candidate)
    {
        var method = candidate?.Method ?? "—";
        var path = candidate?.PathSanitized ?? "—";
        return string.Join(Environment.NewLine, new[]
        {
            "A solicitação será capturada e bloqueada; nada será enviado à ONT.",
            $"Candidatos interceptados: {counters.WriteCandidatesIntercepted}",
            $"Requisições de configuração bloqueadas: {counters.ConfigurationRequestsBlocked}",
            "Requisições de configuração enviadas: 0",
            "Método: " + method,
            "Endpoint sanitizado: " + path,
            $"Quantidade de campos: {candidate?.FieldCount ?? 0}",
            $"Campos sensíveis redigidos: {candidate?.SensitiveFieldCount ?? 0}",
            "Estado da captura: " + counters.WriteCaptureState
        });
    }
}
