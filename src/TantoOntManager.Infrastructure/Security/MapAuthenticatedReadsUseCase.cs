using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.Infrastructure.Security;

public sealed class MapAuthenticatedReadsUseCase : IMapAuthenticatedReadsUseCase
{
    private readonly IOntAuthSessionStore _sessionStore;
    private readonly IAuditLogService _audit;
    private readonly ILogger<MapAuthenticatedReadsUseCase> _logger;

    public MapAuthenticatedReadsUseCase(
        IOntAuthSessionStore sessionStore,
        IAuditLogService audit,
        ILogger<MapAuthenticatedReadsUseCase> logger)
    {
        _sessionStore = sessionStore;
        _audit = audit;
        _logger = logger;
    }

    public async Task<Result<AuthenticatedReadMap>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var transport = _sessionStore.Transport;
        var session = _sessionStore.DomainSession;
        var snapshot = _sessionStore.Snapshot;
        if (transport is null || session is null || snapshot is null || !session.IsAuthenticated)
        {
            return Result.Failure<AuthenticatedReadMap>(Error.Create(
                ErrorCodes.AuthenticatedMapRequiresSession,
                "Mapeie as leituras somente durante uma sessão autenticada."));
        }

        var mapped = await F6201BAuthenticatedReadMapper.MapAsync(transport, snapshot, _logger, cancellationToken);
        if (mapped.Snapshot.FirmwareCompatibility == FirmwareCompatibility.ConfirmedIncompatible)
        {
            _sessionStore.SetState(AuthSessionState.ContractIncompatible);
            transport.ClearCookiesAndState("firmware-incompativel");
            _sessionStore.End("firmware-incompativel");
            var shown = F6201BFirmwareCompatibility.SanitizeForOperator(mapped.Snapshot.Identity.Firmware.SoftwareVersion);
            return Result.Failure<AuthenticatedReadMap>(Error.Create(
                ErrorCodes.ContractIncompatible,
                "A firmware lida (" + shown + ") não é a V9.3.10P8N1 homologada. A sessão foi encerrada."));
        }

        _sessionStore.RememberReadMap(mapped.Map);
        _sessionStore.ReplaceSnapshot(mapped.Snapshot);
        _audit.Record(AuditEvent.Create(
            "map-authenticated-reads",
            "completed",
            "192.168.100.x",
            $"candidatos={mapped.Map.TotalCandidates}; safe={mapped.Map.SafeReadCount}; bloqueados={mapped.Map.BlockedCount}; loginPosts={mapped.Map.LoginPostCount}; configPosts={mapped.Map.ConfigPostCount}"));
        return Result.Success(mapped.Map);
    }
}
