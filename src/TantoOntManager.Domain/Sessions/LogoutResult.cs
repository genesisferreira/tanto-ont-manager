namespace TantoOntManager.Domain.Sessions;

public sealed record LogoutResult(
    bool RemoteInvalidationConfirmed,
    bool CookiesDiscarded,
    string Message,
    int LoginPostCount,
    int LogoutPostCount,
    int ConfigPostCount,
    string? ErrorCode)
{
    public static LogoutResult RemoteConfirmed(int loginPosts, int logoutPosts)
        => new(
            true,
            true,
            "Sessão invalidada na ONT",
            loginPosts,
            logoutPosts,
            0,
            null);

    public static LogoutResult LocalOnly(int loginPosts, int logoutPosts, string? errorCode = null)
        => new(
            false,
            true,
            "Sessão local encerrada; invalidação remota não confirmada",
            loginPosts,
            logoutPosts,
            0,
            errorCode);
}
