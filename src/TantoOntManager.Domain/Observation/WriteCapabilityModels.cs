using TantoOntManager.Domain.Devices;

namespace TantoOntManager.Domain.Observation;

public enum WriteCapabilityConclusion
{
    InsufficientEvidence = 0,
    WriteUiAvailable = 1,
    PppoeOptionUnavailable = 2,
    ReadOnlyAccount = 3,
    PresetLocked = 4
}

public enum WriteCapabilityAvailability
{
    Unconfirmed = 0,
    Available = 1,
    Unavailable = 2
}

public sealed record WriteCapabilityEvidence(
    string Code,
    string Description,
    string Source);

public sealed record ObservedDomControl(
    string Tag,
    string? Name,
    string? Id,
    string Type,
    bool Disabled,
    bool ReadOnly,
    bool Hidden,
    IReadOnlyList<string> OptionValues,
    string? ButtonText,
    string? HandlerName,
    bool Sensitive);

public sealed record WriteCapabilityDomSnapshot(
    IReadOnlyList<string> MenuLeaves,
    IReadOnlyList<ObservedDomControl> Controls,
    bool PageScrolledToFooter);

public sealed record WriteCapabilityContext(
    string? Manufacturer,
    string? Model,
    FirmwareCompatibility Firmware,
    string? SoftwareVersion,
    string? ObservedUsername,
    IReadOnlyList<string> WanProfiles);

public sealed record WriteCapabilityFacts(
    string? Manufacturer,
    string? Model,
    FirmwareCompatibility Firmware,
    string? SoftwareVersion,
    string? ObservedUsername,
    IReadOnlyList<string> MenuLeaves,
    IReadOnlyList<string> WanProfiles,
    IReadOnlyList<string> TypeOptions,
    IReadOnlyList<string> LinkTypeOptions,
    IReadOnlyList<string> IpTypeOptions,
    IReadOnlyList<ObservedDomControl> Controls,
    bool PageScrolledToFooter,
    bool WanPageObserved,
    int WriteCandidatesIntercepted,
    int ConfigurationRequestsSent);

public sealed record WriteCapabilityReport(
    string? Manufacturer,
    string? Model,
    string? SoftwareVersion,
    FirmwareCompatibility Firmware,
    string? ObservedUsername,
    IReadOnlyList<string> MenuLeaves,
    IReadOnlyList<string> WanProfiles,
    IReadOnlyList<string> TypeOptions,
    IReadOnlyList<string> LinkTypeOptions,
    IReadOnlyList<string> IpTypeOptions,
    IReadOnlyList<string> BlockedOrHiddenControls,
    IReadOnlyList<WriteCapabilityEvidence> Evidences,
    WriteCapabilityAvailability PppoeAvailable,
    WriteCapabilityAvailability CreateProfileAvailable,
    WriteCapabilityAvailability ApplySaveAvailable,
    WriteCapabilityConclusion Conclusion,
    string OperatorMessage,
    string NextStep,
    bool PageScrolledToFooter,
    bool WanPageObserved,
    int WriteCandidatesIntercepted,
    int ConfigurationRequestsSent)
{
    public static string AvailabilityLabel(WriteCapabilityAvailability value)
        => value switch
        {
            WriteCapabilityAvailability.Available => "Sim",
            WriteCapabilityAvailability.Unavailable => "Não",
            _ => "Não confirmado"
        };

    public const string PppoeUnavailableOperatorMessage =
        "A interface desta conta/firmware não expõe criação ou edição PPPoE. Nenhuma tentativa de contornar permissões foi realizada. Use credencial oficial com permissão de provisionamento ou solicite à ZTE/fornecedor o contrato de gerenciamento autorizado.";
}
