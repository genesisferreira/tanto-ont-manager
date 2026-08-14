namespace TantoOntManager.Domain.Discovery;

public sealed record AuthenticatedReadMapEntry(
    string? MenuText,
    string Type,
    string Tag,
    string EvidenceSource,
    SafeReadClassification Classification,
    string Reason,
    int? HttpStatus,
    string? ContentType,
    int SizeBytes,
    string? SanitizedHash,
    bool WasAccessed,
    bool IsPriority);

public sealed record AuthenticatedReadMap(
    IReadOnlyList<AuthenticatedReadMapEntry> Entries,
    IReadOnlyList<string> UnresolvedPatterns,
    IReadOnlyList<string> PriorityFound,
    IReadOnlyList<string> PriorityMissing,
    int LoginPostCount,
    int LogoutPostCount,
    int ConfigPostCount,
    string Note)
{
    public int TotalCandidates => Entries.Count;

    public int SafeReadCount => Entries.Count(item => item.Classification == SafeReadClassification.SafeRead);

    public int BlockedCount => Entries.Count(item => item.Classification == SafeReadClassification.BlockedPotentialAction);

    public int DuplicateCount => Entries.Count(item => item.Classification == SafeReadClassification.Duplicate);

    public string ToOperatorText()
    {
        var lines = new List<string>
        {
            "Mapa de leituras autenticadas (sanitizado)",
            $"Candidatos: {TotalCandidates}",
            $"SafeRead: {SafeReadCount}",
            $"Bloqueados: {BlockedCount}",
            $"Duplicados: {DuplicateCount}",
            $"POST login: {LoginPostCount}",
            $"POST logout: {LogoutPostCount}",
            $"POST configuração: {ConfigPostCount}",
            "Prioritárias encontradas: " + (PriorityFound.Count == 0 ? "nenhuma" : string.Join("; ", PriorityFound)),
            "Prioritárias ausentes: " + (PriorityMissing.Count == 0 ? "nenhuma" : string.Join("; ", PriorityMissing)),
            "Padrões sem tag literal: " + (UnresolvedPatterns.Count == 0 ? "nenhum" : string.Join("; ", UnresolvedPatterns)),
            Note,
            string.Empty,
            "Texto do menu | _type | _tag | Origem | Classificação | Motivo | HTTP | Content-Type | Tamanho | Hash"
        };

        foreach (var item in Entries)
        {
            lines.Add(string.Join(" | ", new[]
            {
                item.MenuText ?? "—",
                item.Type,
                item.Tag,
                item.EvidenceSource,
                item.Classification.ToString(),
                item.Reason,
                item.HttpStatus?.ToString() ?? "—",
                item.ContentType ?? "—",
                item.SizeBytes.ToString(),
                item.SanitizedHash ?? "—",
            }));
        }

        return string.Join(Environment.NewLine, lines);
    }
}
