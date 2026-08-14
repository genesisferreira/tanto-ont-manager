using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TantoOntManager.Domain.Audit;

namespace TantoOntManager.Domain.Observation;

public static class ObservationSanitizer
{
    public static string SanitizeText(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var sanitized = SensitiveDataMasker.SanitizeLogText(text);
        sanitized = Regex.Replace(sanitized, "(?i)(_sessionTOKEN|sess_token|SID_HTTPS_|challenge|csrf|nonce)\\s*[:=]\\s*[^\\s,;\"']+", "$1=[redacted]");
        sanitized = Regex.Replace(sanitized, "(?i)(set-cookie|cookie)\\s*[:=]\\s*.+", "$1=[redacted]");
        sanitized = Regex.Replace(sanitized, "(?i)authorization\\s*[:=]\\s*\\S+", "Authorization=[redacted]");
        sanitized = Regex.Replace(
            sanitized,
            "(?i)\\b(loid|serial(number)?|gponsn|mac(address)?)\\s*[:=]\\s*([A-Z0-9:\\-]{4,})",
            match => match.Groups[1].Value + "=[masked]");
        sanitized = Regex.Replace(
            sanitized,
            "(?i)\\b(pppoe\\s*(user(name)?|account)|username)\\s*[:=]\\s*([^\\s,;\"']+)",
            "$1=[masked]");
        sanitized = Regex.Replace(
            sanitized,
            @"(?i)\b([0-9A-F]{2}([:-])){5}[0-9A-F]{2}\b",
            match => SensitiveDataMasker.MaskMac(match.Value));
        return sanitized;
    }

    public static string Sha256(string? text)
    {
        var sanitized = SanitizeText(text);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sanitized))).ToLowerInvariant();
    }

    public static string MaskFieldValue(string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        if (value is "[redacted]" or "[masked]" || value.Contains("**", StringComparison.Ordinal) || value.Contains(".x.x", StringComparison.Ordinal))
        {
            return value;
        }

        if (Regex.IsMatch(key, "(?i)(serial|loid|gponsn)"))
        {
            return SensitiveDataMasker.MaskSerial(value);
        }

        if (Regex.IsMatch(key, "(?i)mac"))
        {
            return SensitiveDataMasker.MaskMac(value);
        }

        if (Regex.IsMatch(key, "(?i)(user|pppoe)") && !Regex.IsMatch(key, "(?i)password"))
        {
            return SensitiveDataMasker.MaskUsername(value);
        }

        if (Regex.IsMatch(value, @"^\d{1,3}(\.\d{1,3}){3}$"))
        {
            return SensitiveDataMasker.MaskIpv4(value);
        }

        if (ObservationUrl.LooksLikeSecret(key, value))
        {
            return "[redacted]";
        }

        var sanitized = SanitizeText(value);
        return sanitized.Length > 48 ? sanitized[..24] + "…" : sanitized;
    }

    public static bool LooksUnsanitized(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        if (Regex.IsMatch(text, "(?i)(set-cookie|SID_HTTPS_=|_sessionTOKEN=)"))
        {
            return true;
        }

        if (Regex.IsMatch(text, "(?i)(password|senha)\\s*[:=]\\s*\\S+"))
        {
            return true;
        }

        if (Regex.IsMatch(text, "(?i)<html|</html>"))
        {
            return true;
        }

        return false;
    }
}
