using TantoOntManager.Domain.Common;

namespace TantoOntManager.Application.Contracts;

public sealed record ExportAuthenticatedDiagnosticCommand(string? Username, string? Password);

public interface IExportAuthenticatedDiagnosticUseCase
{
    Task<Result<string>> ExecuteAsync(
        ExportAuthenticatedDiagnosticCommand command,
        CancellationToken cancellationToken);
}
