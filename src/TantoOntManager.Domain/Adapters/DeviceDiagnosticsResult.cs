using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Diagnostics;

namespace TantoOntManager.Domain.Adapters;

public sealed record DeviceDiagnosticsResult
{
    public bool Succeeded { get; init; }
    public DeviceDiagnostics? Diagnostics { get; init; }
    public Error? Error { get; init; }
    public bool RequiresAuthentication { get; init; }

    public static DeviceDiagnosticsResult Success(DeviceDiagnostics diagnostics)
        => new() { Succeeded = true, Diagnostics = diagnostics };

    public static DeviceDiagnosticsResult Unavailable(Error error, bool requiresAuthentication)
        => new()
        {
            Succeeded = false,
            Error = error,
            RequiresAuthentication = requiresAuthentication
        };
}
