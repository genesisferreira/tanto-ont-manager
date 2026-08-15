using TantoOntManager.Domain.Devices;

namespace TantoOntManager.Domain.Observation;

public enum WriteCapturePhase
{
    Idle = 0,
    Capturing = 1,
    Captured = 2,
    Spent = 3
}

public sealed record WriteCaptureEligibilityInput(
    string? Manufacturer,
    string? Model,
    FirmwareCompatibility Firmware,
    string? SoftwareVersion,
    bool Authenticated,
    string? Confirmation);

public sealed record ObservedWriteField(
    string Name,
    bool Sensitive,
    bool Present,
    string LengthBucket,
    string StructuralType,
    string Value);

public sealed record ObservedWritePayload(
    string? ContentType,
    IReadOnlyList<ObservedWriteField> Fields,
    string? RefererPathSanitized,
    string? Initiator,
    string? ActionName);

public sealed record WriteContractCandidate(
    int Sequence,
    TimeSpan RelativeTime,
    string Screen,
    string Method,
    string PathSanitized,
    IReadOnlyList<string> QueryParameterNames,
    string? ContentType,
    IReadOnlyList<ObservedWriteField> Fields,
    string? ActionName,
    string? RefererPathSanitized,
    string? Initiator,
    IReadOnlyList<string> PrerequisiteGets,
    string StructureSha256,
    bool BlockedBeforeNetwork,
    string BlockReason,
    bool NetworkRequestSent,
    int ConfigurationRequestsSent)
{
    public int FieldCount => Fields.Count;

    public int SensitiveFieldCount => Fields.Count(item => item.Sensitive);
}

public sealed record WriteContractProposalDocument(
    string Status,
    bool NetworkRequestSent,
    bool HumanReviewRequired,
    bool BackupContractRequired,
    bool RollbackContractRequired,
    bool Phase2BRequired,
    bool AdapterModified,
    bool AllowlistModified,
    WriteContractCandidate? Candidate);
