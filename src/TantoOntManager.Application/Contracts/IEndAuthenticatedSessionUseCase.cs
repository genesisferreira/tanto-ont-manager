using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.Application.Contracts;

public sealed record EndAuthenticatedSessionCommand(bool OfficialLogout);

public interface IEndAuthenticatedSessionUseCase
{
    Task<Result<LogoutResult>> ExecuteAsync(
        EndAuthenticatedSessionCommand command,
        CancellationToken cancellationToken);
}
