namespace TantoOntManager.Domain.Observation;

public static class WriteCandidateClassifier
{
    private static readonly HashSet<string> Mutating = new(StringComparer.OrdinalIgnoreCase)
    {
        "POST", "PUT", "PATCH", "DELETE"
    };

    private static readonly HashSet<string> AuthTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "login_entry", "login_token", "logout_entry"
    };

    private static readonly string[] ActionHints =
    [
        "apply", "save", "set", "modify", "create", "delete", "commit", "add", "remove"
    ];

    public static bool IsMutatingMethod(string? method)
    {
        var value = (method ?? string.Empty).Trim().ToUpperInvariant();
        return Mutating.Contains(value) || (value is not "GET" and not "HEAD" and not "");
    }

    public static bool IsAuthenticationControl(Uri uri)
    {
        var type = ObservationUrl.TypeOf(uri);
        var tag = ObservationUrl.TagOf(uri);
        if (string.Equals(type, "loginData", StringComparison.OrdinalIgnoreCase)
            && tag is not null
            && AuthTags.Contains(tag))
        {
            return true;
        }

        return tag is not null && AuthTags.Contains(tag);
    }

    public static bool LooksLikeAsset(Uri uri)
    {
        var path = uri.AbsolutePath;
        return path.Contains("/jquery/", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".css", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".png", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".gif", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".ico", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsWriteCandidate(IncomingObservationRequest request, ObservedWritePayload? payload)
    {
        if (!IsMutatingMethod(request.Method))
        {
            return false;
        }

        if (IsAuthenticationControl(request.Uri) || LooksLikeAsset(request.Uri))
        {
            return false;
        }

        if (HasActionHint(request.Uri, payload))
        {
            return true;
        }

        var method = (request.Method ?? string.Empty).Trim().ToUpperInvariant();
        return method is "POST" or "PUT" or "PATCH" or "DELETE";
    }

    public static string? InferActionName(IncomingObservationRequest request, ObservedWritePayload? payload)
    {
        if (!string.IsNullOrWhiteSpace(payload?.ActionName))
        {
            return payload.ActionName;
        }

        var query = ObservationUrl.ParseQuery(request.Uri.Query);
        if (query.TryGetValue("action", out var action) && !string.IsNullOrWhiteSpace(action))
        {
            return action;
        }

        return ObservationUrl.TagOf(request.Uri);
    }

    private static bool HasActionHint(Uri uri, ObservedWritePayload? payload)
    {
        var haystack = uri.AbsolutePath + uri.Query + " " + (payload?.ActionName ?? string.Empty);
        if (payload is not null)
        {
            haystack += " " + string.Join(' ', payload.Fields.Select(item => item.Name));
        }

        return ActionHints.Any(hint => haystack.Contains(hint, StringComparison.OrdinalIgnoreCase));
    }
}
