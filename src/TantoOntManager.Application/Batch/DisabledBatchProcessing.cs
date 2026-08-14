namespace TantoOntManager.Application.Batch;

public sealed class DisabledBatchProcessingOrchestrator : IBatchProcessingOrchestrator
{
    public bool IsEnabled => false;

    public IReadOnlyList<string> PlannedSteps { get; } =
    [
        "Importar CSV/XLSX",
        "Validar registros",
        "Solicitar conexão física da próxima ONT",
        "Detectar modelo e serial",
        "Cruzar com a linha correta",
        "Fazer backup pelo mecanismo oficial, quando existir",
        "Aplicar preset homologado (desativado nesta fase)",
        "Reiniciar somente quando necessário e homologado",
        "Validar",
        "Registrar sucesso ou falha",
        "Solicitar próxima ONT"
    ];
}

public sealed class UnsupportedBatchWorkOrderReader : IBatchWorkOrderReader
{
    public string Description => "Importação em lote documentada, não implementada na Fase 1.";
}
