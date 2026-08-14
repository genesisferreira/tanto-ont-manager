namespace TantoOntManager.Domain.Common;

public enum ApplicationStatus
{
    Disconnected = 0,
    Detected = 1,
    Authenticated = 2,
    DiagnosticsCompleted = 3,
    ControlledFailure = 4
}

public static class ApplicationStatusDisplay
{
    public static string ToUiLabel(this ApplicationStatus status) => status switch
    {
        ApplicationStatus.Disconnected => "Não conectado",
        ApplicationStatus.Detected => "Detectado",
        ApplicationStatus.Authenticated => "Autenticado",
        ApplicationStatus.DiagnosticsCompleted => "Diagnóstico concluído",
        ApplicationStatus.ControlledFailure => "Falha controlada",
        _ => status.ToString()
    };
}
