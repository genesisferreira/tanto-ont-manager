using System.Text.RegularExpressions;
using TantoOntManager.Domain.Detection;
using TantoOntManager.Domain.Devices;

namespace TantoOntManager.DeviceAdapters.Zte.Parsing;

public sealed record ZtePublicAnalysis(
    bool LooksLikeZte,
    string? Model,
    double Confidence,
    bool LoginFormVisible,
    bool HasConflict,
    DetectionConfidence ConfidenceLevel,
    IReadOnlyList<string> Evidence);

public static class ZtePublicPageAnalyzer
{
    private static readonly Regex NonAlphanumeric = new("[^A-Z0-9]+", RegexOptions.Compiled);

    public static ZtePublicAnalysis Analyze(string? title, string? serverHeader, string? body)
    {
        var raw = $"{title}\n{serverHeader}\n{body}";
        var decoded = WebUtilityDecode(raw);
        var normalized = Collapse(decoded).ToUpperInvariant();
        var compact = NonAlphanumeric.Replace(normalized, string.Empty);
        var evidence = new List<ScoredEvidence>();

        AddIf(evidence, HasPhrase(normalized, "ZTE CORPORATION"), "zte-corporation", "ZTE Corporation", 3, manufacturer: true);
        AddIf(evidence, HasPhrase(normalized, "2008-2025 ZTE") || HasPhrase(normalized, "©2008-2025 ZTE") || HasPhrase(normalized, "(C)2008-2025 ZTE"),
            "zte-copyright", "Rodapé ©2008-2025 ZTE Corporation", 3, manufacturer: true);
        AddIf(evidence, HasIsolatedToken(normalized, "ZXHN"), "zxhn", "Marcador ZXHN", 2, manufacturer: true);
        AddIf(evidence, HasIsolatedToken(normalized, "ZTE"), "zte-brand", "Marca ZTE", 1, manufacturer: true);

        if (!string.IsNullOrWhiteSpace(title))
        {
            evidence.Add(new ScoredEvidence("title", $"Título público: {title.Trim()}", 0, false, false));
        }

        var modelF6201B = HasPhrase(normalized, "WELCOME TO F6201B")
                          || HasPhrase(normalized, "ZXHN F6201B")
                          || HasIsolatedToken(normalized, "F6201B")
                          || compact.Contains("F6201B", StringComparison.Ordinal)
                          || compact.Contains("ZXHNF6201B", StringComparison.Ordinal);
        var modelF6600P = HasIsolatedToken(normalized, "F6600P") || compact.Contains("F6600P", StringComparison.Ordinal);
        var modelF670L = HasIsolatedToken(normalized, "F670L") || compact.Contains("ZXHNF670L", StringComparison.Ordinal);

        AddIf(evidence, HasPhrase(normalized, "WELCOME TO F6201B"), "welcome-f6201b", "Welcome to F6201B", 3, model: true);
        AddIf(evidence, HasPhrase(normalized, "ZXHN F6201B"), "zxhn-f6201b", "ZXHN F6201B", 3, model: true);
        AddIf(evidence, HasIsolatedToken(Collapse(WebUtilityDecode(title ?? string.Empty)).ToUpperInvariant(), "F6201B")
                        || HasPhrase(Collapse(WebUtilityDecode(title ?? string.Empty)).ToUpperInvariant(), "ZXHN F6201B"),
            "title-f6201b", "Título contém F6201B", 2, model: true);
        AddIf(evidence, modelF6201B, "body-f6201b", "Texto F6201B", 2, model: true);
        AddIf(evidence, modelF6600P, "body-f6600p", "Texto F6600P", 2, model: true);
        AddIf(evidence, modelF670L, "body-f670l", "Texto F670L", 2, model: true);

        var loginFormVisible = HasLoginForm(decoded);
        if (loginFormVisible)
        {
            evidence.Add(new ScoredEvidence("login-form", "Formulário de login visível na página pública", 0, false, false));
        }

        var manufacturerScore = evidence.Where(item => item.IsManufacturer).Sum(item => item.Weight);
        var looksLikeZte = manufacturerScore > 0 || HasIsolatedToken(normalized, "ZTE") || HasIsolatedToken(normalized, "ZXHN")
                           || HasPhrase(normalized, "ZTE CORPORATION");

        var models = new List<string>();
        if (modelF6201B)
        {
            models.Add(DeviceModelIds.ZteF6201B);
        }

        if (modelF6600P)
        {
            models.Add(DeviceModelIds.ZteF6600P);
        }

        if (modelF670L)
        {
            models.Add(DeviceModelIds.ZteF670L);
        }

        var distinctModels = models.Distinct().ToList();
        var hasConflict = distinctModels.Count > 1;
        string? model = distinctModels.Count == 1 ? distinctModels[0] : null;

        var modelScore = evidence.Where(item => item.IsModel && (model is null || item.Label.Contains(model.Replace("ZXHN ", string.Empty), StringComparison.OrdinalIgnoreCase) || item.Code.Contains("f6201b", StringComparison.OrdinalIgnoreCase)))
            .Sum(item => item.Weight);

        if (hasConflict)
        {
            var labels = string.Join(", ", evidence.Where(item => item.IsModel).Select(item => item.Label).Distinct());
            return new ZtePublicAnalysis(
                looksLikeZte,
                null,
                0,
                loginFormVisible,
                true,
                DetectionConfidence.Conflict,
                ["Evidências conflitantes de modelo: " + labels]);
        }

        double confidence;
        if (looksLikeZte && model == DeviceModelIds.ZteF6201B && manufacturerScore >= 1 && modelScore >= 2)
        {
            confidence = manufacturerScore >= 3 && modelScore >= 4 ? 0.94 : 0.86;
        }
        else if (looksLikeZte && model is not null && manufacturerScore >= 1 && modelScore >= 2)
        {
            confidence = 0.8;
        }
        else if (looksLikeZte && model is null && manufacturerScore >= 3)
        {
            confidence = 0.48;
        }
        else if (model is not null && manufacturerScore == 0)
        {
            confidence = 0.32;
            model = null;
        }
        else
        {
            confidence = looksLikeZte ? 0.2 : 0;
            model = null;
        }

        if (confidence < 0.35)
        {
            looksLikeZte = looksLikeZte && manufacturerScore >= 1;
        }

        var level = DetectionConfidenceDisplay.FromScore(confidence, false);
        var evidenceLabels = evidence
            .GroupBy(item => item.Code)
            .Select(group => group.First().Label)
            .ToList();

        return new ZtePublicAnalysis(looksLikeZte, model, confidence, loginFormVisible, false, level, evidenceLabels);
    }

    private static void AddIf(
        List<ScoredEvidence> evidence,
        bool condition,
        string code,
        string label,
        int weight,
        bool manufacturer = false,
        bool model = false)
    {
        if (condition && evidence.All(item => item.Code != code))
        {
            evidence.Add(new ScoredEvidence(code, label, weight, manufacturer, model));
        }
    }

    private static string WebUtilityDecode(string value)
    {
        var current = value;
        for (var i = 0; i < 3; i++)
        {
            var decoded = System.Net.WebUtility.HtmlDecode(current);
            if (decoded == current)
            {
                break;
            }

            current = decoded;
        }

        return current.Replace('\u00a0', ' ');
    }

    private static string Collapse(string value)
        => Regex.Replace(value, "\\s+", " ").Trim();

    private static bool HasPhrase(string normalized, string phrase)
        => normalized.Contains(phrase, StringComparison.Ordinal);

    private static bool HasIsolatedToken(string normalized, string token)
    {
        var pattern = $@"(?<![A-Z0-9]){Regex.Escape(token)}(?![A-Z0-9])";
        return Regex.IsMatch(normalized, pattern);
    }

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
