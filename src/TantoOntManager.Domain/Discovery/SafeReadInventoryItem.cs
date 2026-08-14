namespace TantoOntManager.Domain.Discovery;

public sealed record SafeReadInventoryItem(
    string Tag,
    string EvidenceSource,
    string Method,
    string? ContentType,
    int SizeBytes,
    string SanitizedHash,
    SafeReadClassification Classification,
    string ClassificationReason,
    bool WasAccessed)
{
    public string TypeAndTag { get; init; } = Tag;

    public string? MenuText { get; init; }

    public int? HttpStatus { get; init; }

    public SafeReadInventoryItem WithAccess(string? contentType, int sizeBytes, string sanitizedHash)
        => this with
        {
            ContentType = contentType,
            SizeBytes = sizeBytes,
            SanitizedHash = sanitizedHash,
            WasAccessed = true,
            HttpStatus = 200
        };

    public SafeReadInventoryItem WithClassification(SafeReadClassification classification, string reason, bool accessed)
        => this with
        {
            Classification = classification,
            ClassificationReason = reason,
            WasAccessed = accessed
        };
}
