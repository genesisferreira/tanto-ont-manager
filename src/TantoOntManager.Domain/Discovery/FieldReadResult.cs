namespace TantoOntManager.Domain.Discovery;

public enum FieldReadStatus
{
    Read = 0,
    Unavailable = 1,
    NotFound = 2,
    Partial = 3,
    ConfirmedIncompatible = 4,
    ContractNotSatisfied = 5
}

public sealed record FieldReadResult(
    string Field,
    string? SanitizedValue,
    string? SourceEndpoint,
    string? StructuralEvidence,
    FieldReadStatus Status)
{
    public string ToUiValue()
        => Status switch
        {
            FieldReadStatus.Read => string.IsNullOrWhiteSpace(SanitizedValue) ? "—" : SanitizedValue,
            FieldReadStatus.Unavailable => "Não disponível",
            FieldReadStatus.NotFound => "Não localizado nas páginas autenticadas homologadas",
            FieldReadStatus.Partial => "Resposta parcial",
            FieldReadStatus.ConfirmedIncompatible => "Incompatibilidade confirmada",
            FieldReadStatus.ContractNotSatisfied => "Contrato GET não satisfeito (XML genérico)",
            _ => "—"
        };
}

public sealed record HomologatedGetTrace(
    string Screen,
    string LogicalEndpoint,
    string Type,
    string Tag,
    string ExtraParameters,
    int HttpStatus,
    string? ContentType,
    int SizeBytes,
    string ShortHash,
    IReadOnlyList<string> RecognizedFields,
    IReadOnlyList<string> MissingFields,
    string Outcome,
    string? XmlStructure = null)
{
    public string ToOperatorLine()
        => string.Join(" | ", new[]
        {
            Screen,
            LogicalEndpoint,
            "HTTP " + HttpStatus,
            string.IsNullOrWhiteSpace(ContentType) ? "—" : ContentType,
            SizeBytes + " B",
            string.IsNullOrWhiteSpace(ShortHash) ? "—" : ShortHash,
            "reconhecidos: " + (RecognizedFields.Count == 0 ? "nenhum" : string.Join(", ", RecognizedFields)),
            "ausentes: " + (MissingFields.Count == 0 ? "nenhum" : string.Join(", ", MissingFields)),
            Outcome,
            string.IsNullOrWhiteSpace(XmlStructure) ? "—" : XmlStructure
        });
}
