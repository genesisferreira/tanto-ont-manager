namespace TantoOntManager.Domain.Discovery;

public sealed record DirectedReadStep(
    string Priority,
    string StartPage,
    string? DataEndpoint,
    string Result,
    string? MissingReason,
    int GetsUsed,
    int GetBudget);
