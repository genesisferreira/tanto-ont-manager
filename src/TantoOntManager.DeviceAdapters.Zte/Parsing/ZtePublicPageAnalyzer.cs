using System.Text.RegularExpressions;
using TantoOntManager.Domain.Devices;

namespace TantoOntManager.DeviceAdapters.Zte.Parsing;

public sealed record ZtePublicAnalysis(
    bool LooksLikeZte,
    string? Model,
    double Confidence,
    bool LoginFormVisible,
    IReadOnlyList<string> Evidence);

public static class ZtePublicPageAnalyzer
{
    public static ZtePublicAnalysis Analyze(string? title, string? serverHeader, string? body)
    {
        var evidence = new List<string>();
        var haystack = $"{title}{Environment.NewLine}{serverHeader}{Environment.NewLine}{body}";
        var normalized = haystack.ToUpperInvariant();

        var looksLikeZte = ContainsToken(normalized, "ZTE") || ContainsToken(normalized, "ZXHN");
        if (ContainsToken(normalized, "ZTE"))
        {
            evidence.Add("Marcador público ZTE");
        }

        if (ContainsToken(normalized, "ZXHN"))
        {
            evidence.Add("Marcador público ZXHN");
        }

        if (!string.IsNullOrWhiteSpace(title))
        {
            evidence.Add($"Título público: {title.Trim()}");
        }

        if (!string.IsNullOrWhiteSpace(serverHeader))
        {
            evidence.Add($"Cabeçalho Server: {serverHeader.Trim()}");
        }

        var model = DetectModel(normalized, evidence);
        var loginFormVisible = HasLoginForm(body);

        if (loginFormVisible)
        {
            evidence.Add("Formulário de login visível na página pública");
        }

        var confidence = 0d;
        if (looksLikeZte)
        {
            confidence = 0.45;
        }

        if (model == DeviceModelIds.ZteF6201B)
        {
            confidence = titleContainsModel(title, DeviceModelIds.ZteF6201B) ? 0.93 : 0.82;
        }
        else if (model is DeviceModelIds.ZteF6600P or DeviceModelIds.ZteF670L)
        {
            confidence = 0.8;
        }

        if (!looksLikeZte && model is null)
        {
            confidence = 0;
            evidence.Clear();
        }

        return new ZtePublicAnalysis(looksLikeZte, model, confidence, loginFormVisible, evidence);
    }

    private static string? DetectModel(string normalized, List<string> evidence)
    {
        if (normalized.Contains("F6201B", StringComparison.Ordinal) || normalized.Contains("ZXHN F6201B", StringComparison.Ordinal))
        {
            evidence.Add("Modelo público F6201B");
            return DeviceModelIds.ZteF6201B;
        }

        if (normalized.Contains("F6600P", StringComparison.Ordinal))
        {
            evidence.Add("Modelo público F6600P");
            return DeviceModelIds.ZteF6600P;
        }

        if (normalized.Contains("F670L", StringComparison.Ordinal))
        {
            evidence.Add("Modelo público F670L");
            return DeviceModelIds.ZteF670L;
        }

        return null;
    }

    private static bool titleContainsModel(string? title, string model)
        => !string.IsNullOrWhiteSpace(title)
           && title.Contains(model, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsToken(string normalized, string token)
        => Regex.IsMatch(normalized, $@"\b{Regex.Escape(token)}\b", RegexOptions.CultureInvariant);

    private static bool HasLoginForm(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        var lower = body.ToLowerInvariant();
        return lower.Contains("type=\"password\"")
               || lower.Contains("type='password'")
               || lower.Contains("name=\"password\"")
               || lower.Contains("name=\"pwd\"");
    }
}
