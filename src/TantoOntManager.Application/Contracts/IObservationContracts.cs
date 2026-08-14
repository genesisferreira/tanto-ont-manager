using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.Application.Contracts;

public interface IObservationSessionStore
{
    ObservationEngine? Engine { get; }

    ObservationSnapshot? LastSnapshot { get; }

    string? UserDataFolder { get; }

    bool IsOpen { get; }

    bool TemporaryCookiesDestroyed { get; }

    void Attach(ObservationEngine engine, string userDataFolder);

    ObservationSnapshot FinishAndDestroy();

    void ClearSnapshot();
}

public interface IExportObservationUseCase
{
    Task<Result<ObservationExportResult>> ExecuteAsync(CancellationToken cancellationToken);
}

public interface IPromoteReadContractUseCase
{
    Task<Result<string>> ExecuteAsync(CancellationToken cancellationToken);
}
