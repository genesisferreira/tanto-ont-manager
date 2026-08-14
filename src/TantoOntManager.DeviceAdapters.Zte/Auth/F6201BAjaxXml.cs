using System.Xml.Linq;
using TantoOntManager.Security.Export;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public sealed record SanitizedAjaxXmlStructure(
    string Root,
    IReadOnlyList<string> ElementNames,
    int NodeCount,
    bool HasErrorFields,
    string? ErrorId,
    string? ErrorType,
    string? ErrorStr,
    bool HasParaName,
    bool HasInstance,
    bool HasCharacteristicObject,
    int SizeBytes,
    string ShortHash)
{
    public bool IsGenericAck
        => string.Equals(Root, F6201BV9310P8N1AuthContract.XmlChallengeRoot, StringComparison.OrdinalIgnoreCase)
           && HasErrorFields
           && !HasParaName
           && !HasInstance
           && !HasCharacteristicObject;

    public string ToOperatorText()
        => string.Join(" | ", new[]
        {
            "raiz=" + (string.IsNullOrWhiteSpace(Root) ? "—" : Root),
            "elementos=" + (ElementNames.Count == 0 ? "—" : string.Join(",", ElementNames)),
            "nós=" + NodeCount,
            HasErrorFields ? "erros=sim" : "erros=não",
            "IF_ERRORID=" + (ErrorId ?? "—"),
            "IF_ERRORTYPE=" + (ErrorType ?? "—"),
            "IF_ERRORSTR=" + (ErrorStr ?? "—"),
            SizeBytes + " B",
            "hash=" + ShortHash
        });
}

public static class F6201BAjaxXml
{
    private static readonly HashSet<string> ErrorElements = new(StringComparer.OrdinalIgnoreCase)
    {
        "IF_ERRORPARAM", "IF_ERRORTYPE", "IF_ERRORSTR", "IF_ERRORID"
    };

    public static SanitizedAjaxXmlStructure Inspect(string? body)
    {
        var text = body ?? string.Empty;
        var hash = AuthenticatedPayloadSanitizer.Sha256Short(text);
        if (string.IsNullOrWhiteSpace(text))
        {
            return new SanitizedAjaxXmlStructure(
                string.Empty, [], 0, false, null, null, null, false, false, false, 0, hash);
        }

        try
        {
            var document = XDocument.Parse(text, LoadOptions.None);
            var names = document.Descendants()
                .Select(node => node.Name.LocalName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(40)
                .ToList();
            var root = document.Root?.Name.LocalName ?? string.Empty;
            var errorId = TextOf(document, "IF_ERRORID");
            var errorType = TextOf(document, "IF_ERRORTYPE");
            var errorStr = TextOf(document, "IF_ERRORSTR");
            return new SanitizedAjaxXmlStructure(
                root,
                names,
                document.Descendants().Count(),
                names.Any(name => ErrorElements.Contains(name)),
                errorId,
                errorType,
                string.IsNullOrWhiteSpace(errorStr) ? errorStr : (errorStr.Length > 24 ? errorStr[..24] : errorStr),
                names.Contains("ParaName", StringComparer.OrdinalIgnoreCase),
                names.Contains("Instance", StringComparer.OrdinalIgnoreCase),
                names.Any(name => name.StartsWith("OBJ_", StringComparison.OrdinalIgnoreCase)
                                  || name.StartsWith("ID_WAN", StringComparison.OrdinalIgnoreCase)),
                text.Length,
                hash);
        }
        catch
        {
            return new SanitizedAjaxXmlStructure(
                "xml-invalido", [], 0, false, null, null, null, false, false, false, text.Length, hash);
        }
    }

    public static bool IsGenericAck(string? body)
        => Inspect(body).IsGenericAck;

    public static bool SatisfiesContract(string? body, IReadOnlyList<string> characteristicMarkers)
    {
        var structure = Inspect(body);
        if (structure.IsGenericAck || !structure.HasParaName || !structure.HasInstance)
        {
            return false;
        }

        if (characteristicMarkers.Count == 0)
        {
            return structure.HasCharacteristicObject;
        }

        var compact = body ?? string.Empty;
        return characteristicMarkers.Any(marker => compact.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static string? TextOf(XDocument document, string name)
        => document.Descendants().FirstOrDefault(node =>
               node.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))
           ?.Value.Trim();
}
