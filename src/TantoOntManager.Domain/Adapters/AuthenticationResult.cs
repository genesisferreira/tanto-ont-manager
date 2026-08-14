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
    public AuthorizedDeviceSession? Session { get; init; }
    public Error? Error { get; init; }

    public static AuthenticationResult MethodNotMapped(string manufacturer, string? model, string? firmware)
        => new()
        {
            Outcome = AuthenticationOutcome.MethodNotMapped,
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
            Error = Error.Create(
                ErrorCodes.AuthenticationNotAttempted,
                "A autenticação não foi tentada.",
                "O diagnóstico público permanece disponível sem login.")
        };
}
