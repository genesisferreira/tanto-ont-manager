namespace TantoOntManager.Domain.Discovery;

public sealed record FieldEvidence(
    string Field,
    string? Value,
    string SourcePage,
    string Strategy,
    string Snippet)
{
    public string? EndpointType { get; init; }

    public string? FieldKey { get; init; }

    public string? ResponseHash { get; init; }
}
