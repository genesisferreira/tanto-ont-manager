using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Detection;

namespace TantoOntManager.Application.Contracts;

public sealed record ExportPublicDiagnosticCommand(string? Username, string? Password);

public interface IExportPublicDiagnosticUseCase
{
    Task<Result<string>> ExecuteAsync(ExportPublicDiagnosticCommand command, CancellationToken cancellationToken);
}
