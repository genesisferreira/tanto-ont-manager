namespace TantoOntManager.Domain.Detection;

public enum DetectionConfidence
{
    Insufficient = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Conflict = 4
}

public static class DetectionConfidenceDisplay
{
    public static string ToUiLabel(this DetectionConfidence confidence) => confidence switch
    {
        DetectionConfidence.High => "Alta",
        DetectionConfidence.Medium => "Média",
        DetectionConfidence.Low => "Baixa",
        DetectionConfidence.Conflict => "Conflito",
        _ => "Insuficiente"
    };

    public static DetectionConfidence FromScore(double score, bool conflict)
    {
        if (conflict)
        {
            return DetectionConfidence.Conflict;
        }

        return score switch
        {
            >= 0.85 => DetectionConfidence.High,
            >= 0.55 => DetectionConfidence.Medium,
            >= 0.35 => DetectionConfidence.Low,
            _ => DetectionConfidence.Insufficient
        };
    }
}
