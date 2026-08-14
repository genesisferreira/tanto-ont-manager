namespace TantoOntManager.Domain.Common;

public sealed record Error
{
    public string Code { get; }
    public string Message { get; }
    public string? Recommendation { get; }

    private Error(string code, string message, string? recommendation)
    {
        Code = code;
        Message = message;
        Recommendation = recommendation;
    }

    public static Error Create(string code, string message, string? recommendation = null)
        => new(code, message, recommendation);
}
