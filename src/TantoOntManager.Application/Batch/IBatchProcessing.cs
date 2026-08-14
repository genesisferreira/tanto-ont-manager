namespace TantoOntManager.Application.Batch;

/// <summary>
/// Fluxo futuro de processamento em lote. Não aplica configuração nesta fase.
/// </summary>
public interface IBatchWorkOrderReader
{
    string Description { get; }
}

public interface IBatchProcessingOrchestrator
{
    bool IsEnabled { get; }

    IReadOnlyList<string> PlannedSteps { get; }
}
