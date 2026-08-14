namespace TantoOntManager.Domain.Common;

public enum OperationMode
{
    LaboratoryReadOnly = 0
}

public static class OperationModeDisplay
{
    public static string ToUiLabel(this OperationMode mode) => mode switch
    {
        OperationMode.LaboratoryReadOnly => "Laboratório — somente leitura",
        _ => mode.ToString()
    };
}
