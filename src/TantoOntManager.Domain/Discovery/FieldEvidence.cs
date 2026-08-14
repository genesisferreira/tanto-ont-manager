namespace TantoOntManager.Domain.Discovery;

public sealed record FieldEvidence(
    string Field,
    string? Value,
    string SourcePage,
    string Strategy,
    string Snippet);
