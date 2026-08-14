namespace TantoOntManager.Domain.Audit;

public sealed record AuditEvent(
    DateTimeOffset OccurredAt,
    string Action,
    string Outcome,
    string? TargetAddress,
    string Details)
{
    public static AuditEvent Create(string action, string outcome, string? targetAddress, string details)
        => new(DateTimeOffset.UtcNow, action, outcome, targetAddress, details);
}
