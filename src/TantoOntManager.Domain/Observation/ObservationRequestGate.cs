using System.Net;
using System.Text.RegularExpressions;

namespace TantoOntManager.Domain.Observation;

public static class ObservationRequestGate
{
    public static readonly IReadOnlyList<string> AllowedMethods = ["GET", "HEAD"];

    public static readonly IReadOnlyList<string> BlockedMethods = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"];

    private static readonly HashSet<string> ActionTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "apply", "save", "submit", "create", "delete", "remove", "reset", "reboot",
        "upgrade", "upload", "restore", "factory", "firmware", "modify", "set",
        "commit", "write", "download", "logout", "logoff", "chgpwd"
    };

    public static ObservationDecision Evaluate(
        IncomingObservationRequest request,
        IPAddress boundAddress,
        bool cancelled,
        bool allowManualLoginPost = false)
    {
        if (cancelled)
        {
            return new ObservationDecision(false, "Observação cancelada; requisição pendente interrompida.", true);
        }

        if (request.IsNewWindow)
        {
            return new ObservationDecision(false, "Abertura de nova janela bloqueada.");
        }

        if (request.IsDownload)
        {
            return new ObservationDecision(false, "Download bloqueado.");
        }

        if (!ObservationHosts.IsBoundHost(request.Uri, boundAddress))
        {
            return new ObservationDecision(false, "Destino diferente do IP da ONT selecionada.", true);
        }

        if (request.RedirectLocation is not null && !ObservationHosts.IsBoundHost(request.RedirectLocation, boundAddress))
        {
            return new ObservationDecision(false, "Redirect para outro host bloqueado.", true);
        }

        var method = (request.Method ?? string.Empty).Trim().ToUpperInvariant();
        if (method == "POST" && allowManualLoginPost && IsManualLoginPost(request.Uri))
        {
            return new ObservationDecision(false, "POST de login manual no observador não está habilitado nesta entrega; reutilize a sessão autenticada.");
        }

        if (!AllowedMethods.Contains(method, StringComparer.OrdinalIgnoreCase))
        {
            var reason = method == "POST"
                ? "POST bloqueado no observador."
                : $"Método {method} bloqueado; somente GET/HEAD.";
            return new ObservationDecision(false, reason);
        }

        if (HasActionToken(request.Uri))
        {
            return new ObservationDecision(false, "Token de ação na URL; GET/HEAD bloqueado.");
        }

        return new ObservationDecision(true, "GET/HEAD no IP da ONT, sem token de ação.");
    }

    public static bool HasActionToken(Uri uri)
    {
        var tag = ObservationUrl.TagOf(uri);
        if (!string.IsNullOrWhiteSpace(tag) && Tokenize(tag).Any(ActionTokens.Contains))
        {
            return true;
        }

        var path = uri.AbsolutePath + uri.Query;
        foreach (var token in Tokenize(path.Replace('/', '_').Replace('?', '_').Replace('&', '_').Replace('=', '_')))
        {
            if (ActionTokens.Contains(token))
            {
                return true;
            }
        }

        var query = ObservationUrl.ParseQuery(uri.Query);
        if (query.TryGetValue("action", out var action) && ActionTokens.Contains(action))
        {
            return true;
        }

        return Regex.IsMatch(path, "(?i)(apply|save|create|delete|modify|reboot|reset|upgrade|upload|commit)\\b");
    }

    public static IReadOnlyList<string> Tokenize(string text)
    {
        var tokens = new List<string>();
        foreach (var part in text.Split(['_', '-', '.', ',', ';', ':'], StringSplitOptions.RemoveEmptyEntries))
        {
            var pieces = Regex.Split(part, "(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])");
            foreach (var piece in pieces)
            {
                if (!string.IsNullOrWhiteSpace(piece) && piece.Length >= 3)
                {
                    tokens.Add(piece);
                }
            }
        }

        return tokens;
    }

    private static bool IsManualLoginPost(Uri uri)
    {
        var type = ObservationUrl.TypeOf(uri);
        var tag = ObservationUrl.TagOf(uri);
        return string.Equals(type, "loginData", StringComparison.OrdinalIgnoreCase)
               && string.Equals(tag, "login_entry", StringComparison.OrdinalIgnoreCase);
    }
}
