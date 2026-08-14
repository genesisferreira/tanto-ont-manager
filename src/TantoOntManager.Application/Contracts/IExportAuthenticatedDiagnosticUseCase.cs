using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Export;

namespace TantoOntManager.Application.Contracts;

public sealed record ExportAuthenticatedDiagnosticCommand(string? Username, string? Password);

public interface IExportAuthenticatedDiagnosticUseCase
{
    Task<Result<AuthenticatedExportResult>> ExecuteAsync(
        ExportAuthenticatedDiagnosticCommand command,
        CancellationToken cancellationToken);
}
