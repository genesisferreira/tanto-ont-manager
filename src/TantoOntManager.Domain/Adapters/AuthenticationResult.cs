using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.Domain.Adapters;

public enum AuthenticationOutcome
{
    NotAttempted = 0,
    MethodNotMapped = 1,
    Succeeded = 2,
    Failed = 3
}

public sealed record AuthenticationResult
{
    public AuthenticationOutcome Outcome { get; init; }
    public AuthSessionState SessionState { get; init; }
    public AuthorizedDeviceSession? Session { get; init; }
    public AuthenticatedReadSnapshot? Snapshot { get; init; }
    public Error? Error { get; init; }
    public int PostCount { get; init; }
    public int RedirectCount { get; init; }
    public int? HttpStatus { get; init; }
    public string? MaskedEndpoint { get; init; }
    public string? SanitizedResponseHash { get; init; }
    public TimeSpan Duration { get; init; }
    public IReadOnlyList<string> PagesRead { get; init; } = [];

    public static AuthenticationResult MethodNotMapped(string manufacturer, string? model, string? firmware)
        => new()
        {
            Outcome = AuthenticationOutcome.MethodNotMapped,
            SessionState = AuthSessionState.Unmapped,
            Error = Error.Create(
                ErrorCodes.AuthenticationMethodNotMapped,
                "O método de autenticação desta ONT ainda não foi mapeado.",
                $"Fabricante: {manufacturer}. Modelo: {model ?? "não confirmado"}. Firmware: {firmware ?? "não confirmada"}. " +
                "Nenhum usuário ou senha foi enviado. Nenhum endpoint de login foi inventado.")
        };

    public static AuthenticationResult NotAttempted()
        => new()
        {
            Outcome = AuthenticationOutcome.NotAttempted,
            SessionState = AuthSessionState.Unmapped,
            Error = Error.Create(
                ErrorCodes.AuthenticationNotAttempted,
                "A autenticação não foi tentada.",
                "O diagnóstico público permanece disponível sem login.")
        };

    public static AuthenticationResult Succeeded(
        AuthorizedDeviceSession session,
        AuthenticatedReadSnapshot snapshot,
        int? httpStatus,
        string maskedEndpoint,
        TimeSpan duration)
        => new()
        {
            Outcome = AuthenticationOutcome.Succeeded,
            SessionState = AuthSessionState.AuthenticatedReadOnly,
            Session = session,
            Snapshot = snapshot,
            PostCount = snapshot.PostCount,
            RedirectCount = snapshot.RedirectCount,
            HttpStatus = httpStatus,
            MaskedEndpoint = maskedEndpoint,
            SanitizedResponseHash = snapshot.LastSanitizedHash,
            Duration = duration,
            PagesRead = snapshot.PagesRead
        };

    public static AuthenticationResult Failed(
        AuthSessionState state,
        Error error,
        int postCount = 0,
        int redirectCount = 0,
        int? httpStatus = null,
        string? maskedEndpoint = null,
        string? sanitizedHash = null,
        TimeSpan duration = default)
        => new()
        {
            Outcome = AuthenticationOutcome.Failed,
            SessionState = state,
            Error = error,
            PostCount = postCount,
            RedirectCount = redirectCount,
            HttpStatus = httpStatus,
            MaskedEndpoint = maskedEndpoint,
            SanitizedResponseHash = sanitizedHash,
            Duration = duration
        };
}
