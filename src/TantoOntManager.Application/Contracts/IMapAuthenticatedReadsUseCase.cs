using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Discovery;
using TantoOntManager.Domain.Export;

namespace TantoOntManager.Application.Contracts;

public interface IMapAuthenticatedReadsUseCase
{
    Task<Result<AuthenticatedReadMap>> ExecuteAsync(CancellationToken cancellationToken);
}

public interface IExportAuthenticatedReadMapUseCase
{
    Task<Result<AuthenticatedExportResult>> ExecuteAsync(CancellationToken cancellationToken);
}
