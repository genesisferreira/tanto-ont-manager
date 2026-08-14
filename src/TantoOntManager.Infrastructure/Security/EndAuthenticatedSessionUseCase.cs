using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.Infrastructure.Security;

public sealed class EndAuthenticatedSessionUseCase : IEndAuthenticatedSessionUseCase
{
    private readonly IOntAuthSessionStore _sessionStore;
    private readonly IAuditLogService _audit;
    private readonly ILogger<EndAuthenticatedSessionUseCase> _logger;

    public EndAuthenticatedSessionUseCase(
        IOntAuthSessionStore sessionStore,
        IAuditLogService audit,
        ILogger<EndAuthenticatedSessionUseCase> logger)
    {
        _sessionStore = sessionStore;
        _audit = audit;
        _logger = logger;
    }

    public async Task<Result<LogoutResult>> ExecuteAsync(
        EndAuthenticatedSessionCommand command,
        CancellationToken cancellationToken)
    {
        var transport = _sessionStore.Transport;
        var loginPosts = transport?.LoginPostCount ?? 0;
        LogoutResult result;

        if (command.OfficialLogout && transport is not null)
        {
            result = await F6201BV9310P8N1Logout.ExecuteAsync(transport, cancellationToken);
        }
        else
        {
            transport?.ClearCookiesAndState("end-without-official-logout");
            result = LogoutResult.LocalOnly(loginPosts, transport?.LogoutPostCount ?? 0);
        }

        _sessionStore.End("operador");
        _audit.Record(AuditEvent.Create(
            "end-session",
            result.RemoteInvalidationConfirmed ? "remote-invalidated" : "local-only",
            "192.168.100.x",
            $"loginPosts={result.LoginPostCount}; logoutPosts={result.LogoutPostCount}; configPosts={result.ConfigPostCount}"));
        _logger.LogInformation(
            "Sessão encerrada remoto={Remote} loginPosts={Login} logoutPosts={Logout} configPosts={Config}",
            result.RemoteInvalidationConfirmed,
            result.LoginPostCount,
            result.LogoutPostCount,
            result.ConfigPostCount);
        return Result.Success(result);
    }
}
