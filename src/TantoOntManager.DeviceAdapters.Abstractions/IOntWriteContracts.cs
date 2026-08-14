namespace TantoOntManager.DeviceAdapters.Abstractions;

/// <summary>
/// Operações de escrita futuras. Nenhum método desta interface é implementado na Fase 1.
/// Contratos serão específicos (WAN, backup, preset) — nunca ExecuteCommand/PostRawRequest.
/// </summary>
public interface IOntWriteAdapter
{
    bool IsHomologated { get; }

    string HomologationRequirement { get; }
}

public interface IOntBackupAdapter
{
    bool OfficialBackupAvailable { get; }
}

public interface IOntPresetAdapter
{
    bool HomologatedPresetAvailable { get; }
}
