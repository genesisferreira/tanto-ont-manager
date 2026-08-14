namespace TantoOntManager.Domain.Observation;

public static class ObservationClassifier
{
    private static readonly string[] AssetExtensions =
    [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".map", ".lp"
    ];

    private static readonly HashSet<string> AuthTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "login_entry", "login_token", "logout_entry", "switchlang_entry", "modeswitch_entry"
    };

    public static ObservedGetClassification Classify(Uri uri, ObservationDecision decision)
    {
        if (!decision.Allowed || ObservationRequestGate.HasActionToken(uri))
        {
            return ObservedGetClassification.PotentialAction;
        }

        var type = ObservationUrl.TypeOf(uri);
        var tag = ObservationUrl.TagOf(uri);
        if (string.Equals(type, "loginData", StringComparison.OrdinalIgnoreCase)
            || (!string.IsNullOrWhiteSpace(tag) && AuthTags.Contains(tag)))
        {
            return ObservedGetClassification.AuthenticationControl;
        }

        if (IsAsset(uri))
        {
            return ObservedGetClassification.Asset;
        }

        if (string.Equals(type, "menuView", StringComparison.OrdinalIgnoreCase))
        {
            return ObservedGetClassification.Template;
        }

        if (string.Equals(type, "menuData", StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "hiddenData", StringComparison.OrdinalIgnoreCase))
        {
            return ObservedGetClassification.DataEndpoint;
        }

        return ObservedGetClassification.Unknown;
    }

    public static bool IsAsset(Uri uri)
    {
        var path = uri.AbsolutePath;
        return AssetExtensions.Any(ext => path.EndsWith(ext, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsPriorityCandidate(ObservedGetClassification classification, bool isNewOrChanged)
        => isNewOrChanged && classification is ObservedGetClassification.DataEndpoint or ObservedGetClassification.Template;
}
