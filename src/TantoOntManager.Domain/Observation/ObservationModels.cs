using System.Net;

namespace TantoOntManager.Domain.Observation;

public enum ObservedGetClassification
{
    Template = 0,
    DataEndpoint = 1,
    Asset = 2,
    AuthenticationControl = 3,
    PotentialAction = 4,
    Unknown = 5
}

public enum ObservationScreen
{
    Shell = 0,
    Device = 1,
    Pon = 2,
    WanStatus = 3,
    WanConfig = 4
}

public sealed record IncomingObservationRequest(
    string Method,
    Uri Uri,
    Uri? RedirectLocation = null,
    bool IsDownload = false,
    bool IsNewWindow = false,
    string? Initiator = null);

public sealed record ObservationDecision(
    bool Allowed,
    string Reason,
    bool EndsObservation = false);

public sealed record ObservedGetRecord(
    int Sequence,
    TimeSpan RelativeTime,
    ObservationScreen Screen,
    string Path,
    string? Type,
    string? Tag,
    IReadOnlyList<string> ExtraParameterNames,
    IReadOnlyDictionary<string, string> ExtraValuesSanitized,
    string Method,
    int? StatusCode,
    string? ContentType,
    int SizeBytes,
    string Sha256,
    string? Initiator,
    ObservedGetClassification Classification,
    bool IsBaseline,
    bool IsNewOrChanged,
    string NormalizedUrl);

public sealed record BlockedRequestRecord(
    int Sequence,
    TimeSpan RelativeTime,
    string Method,
    string PathSanitized,
    string Reason,
    string Host);

public sealed record ObservationCounters(
    int GetsObserved,
    int GetsAllowed,
    int RequestsBlocked,
    int PostsObservedAndBlocked,
    int ConfigurationPostsSent)
{
    public static ObservationCounters Zero { get; } = new(0, 0, 0, 0, 0);
}

public sealed record ResponseStructure(
    string NormalizedUrl,
    string Format,
    IReadOnlyList<string> Keys,
    IReadOnlyList<string> FieldIds,
    IReadOnlyList<string> ColumnNames,
    int RecordCount,
    IReadOnlyDictionary<string, string> ApproximateTypes,
    IReadOnlyDictionary<string, string> MaskedSampleValues);

public sealed record ReadContractProposal(
    string FirmwareTarget,
    string FirmwareStatus,
    ObservationScreen Screen,
    string Endpoint,
    string? Type,
    string? Tag,
    IReadOnlyList<string> RequiredParameters,
    IReadOnlyList<string> VariableParameters,
    string ResponseFormat,
    IReadOnlyList<string> ObservedFields,
    string Evidence,
    string Risk,
    string ParserRecommendation,
    bool WriteForbidden);

public sealed record ObservationZipInspection(
    bool IncludesCookies,
    bool IncludesCredentials,
    bool IncludesTokens,
    bool IncludesRawAuthenticatedBody,
    bool SensitiveIdentifiersMasked,
    int ConfigurationRequestsSent,
    IReadOnlyList<string> EntryNames)
{
    public bool IsAcceptable
        => !IncludesCookies
           && !IncludesCredentials
           && !IncludesTokens
           && !IncludesRawAuthenticatedBody
           && SensitiveIdentifiersMasked
           && ConfigurationRequestsSent == 0;

    public string ToOperatorText()
        => string.Join(Environment.NewLine, new[]
        {
            $"IncludesCookies: {IncludesCookies.ToString().ToLowerInvariant()}",
            $"IncludesCredentials: {IncludesCredentials.ToString().ToLowerInvariant()}",
            $"IncludesTokens: {IncludesTokens.ToString().ToLowerInvariant()}",
            $"IncludesRawAuthenticatedBody: {IncludesRawAuthenticatedBody.ToString().ToLowerInvariant()}",
            $"SensitiveIdentifiersMasked: {SensitiveIdentifiersMasked.ToString().ToLowerInvariant()}",
            $"ConfigurationRequestsSent: {ConfigurationRequestsSent}"
        });
}

public sealed record ObservationExportResult(string ZipPath, ObservationZipInspection Inspection);

public sealed record ObservationSnapshot(
    System.Net.IPAddress BoundAddress,
    ObservationCounters Counters,
    IReadOnlyList<ObservedGetRecord> Gets,
    IReadOnlyList<BlockedRequestRecord> Blocked,
    IReadOnlyList<ResponseStructure> Structures,
    string TableText,
    string SummaryText);

public static class ObservationScreens
{
    public const int CaptureSeconds = 20;

    public static string ToOperatorLabel(this ObservationScreen screen) => screen switch
    {
        ObservationScreen.Shell => "Shell inicial",
        ObservationScreen.Device => "Device",
        ObservationScreen.Pon => "PON",
        ObservationScreen.WanStatus => "WAN Status",
        ObservationScreen.WanConfig => "WAN Config",
        _ => screen.ToString()
    };
}

public static class ObservationHosts
{
    public static bool IsBoundHost(Uri uri, IPAddress boundAddress)
    {
        if (uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
        {
            return IPAddress.TryParse(uri.Host, out var host) && host.Equals(boundAddress);
        }

        return uri.Host.Equals(boundAddress.ToString(), StringComparison.OrdinalIgnoreCase);
    }
}
