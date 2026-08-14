using System.Text.RegularExpressions;

namespace TantoOntManager.Security.Export;

public sealed record SecretScanResult(bool Blocked, IReadOnlyList<string> Reasons)
{
    public static SecretScanResult Ok { get; } = new(false, []);
}

public static class PublicExportSecretScanner
{
    private static readonly Regex SetCookieHeaderInBody = new(
        @"(?im)^set-cookie\s*:",
        RegexOptions.Compiled);

    private static readonly Regex AuthorizationAssignment = new(
        @"(?i)\bauthorization\s*[:=]\s*(bearer\s+)?[A-Za-z0-9\-._~+/]+=*",
        RegexOptions.Compiled);

    public static SecretScanResult Scan(
        string html,
        IReadOnlyList<string> safeHeaders,
        string? username,
        string? password)
    {
        var reasons = new List<string>();

        if (safeHeaders.Any(IsSensitiveHeader))
        {
            reasons.Add("Cabeçalho Cookie, Set-Cookie ou Authorization presente no pacote.");
        }

        if (SetCookieHeaderInBody.IsMatch(html))
        {
            reasons.Add("Texto Set-Cookie detectado no HTML público.");
        }

        if (AuthorizationAssignment.IsMatch(html))
        {
            reasons.Add("Possível token de autorização no HTML público.");
        }

        if (!string.IsNullOrWhiteSpace(username) && username.Length >= 3 && html.Contains(username, StringComparison.Ordinal))
        {
            reasons.Add("O HTML público contém o usuário digitado na interface.");
        }

        if (!string.IsNullOrWhiteSpace(password) && password.Length >= 3 && html.Contains(password, StringComparison.Ordinal))
        {
            reasons.Add("O HTML público contém a senha digitada na interface.");
        }

        return reasons.Count == 0 ? SecretScanResult.Ok : new SecretScanResult(true, reasons);
    }

    private static bool IsSensitiveHeader(string header)
        => header.StartsWith("Set-Cookie", StringComparison.OrdinalIgnoreCase)
           || header.StartsWith("Cookie:", StringComparison.OrdinalIgnoreCase)
           || header.StartsWith("Authorization", StringComparison.OrdinalIgnoreCase)
           || header.StartsWith("Proxy-Authorization", StringComparison.OrdinalIgnoreCase);
}
