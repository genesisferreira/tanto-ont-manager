namespace TantoOntManager.Domain.Diagnostics;

public sealed record OperatorRecommendation(
    string Code,
    string Title,
    string Details,
    bool IsBlocking)
{
    public static OperatorRecommendation SubnetMismatch(string details)
        => new("SUBNET", "Sub-rede incompatível", details, true);

    public static OperatorRecommendation TrustLocalCertificate()
        => new(
            "TLS",
            "Certificado local não confiável",
            "A ONT de laboratório usa HTTPS com certificado self-signed. A confiança vale somente para o IP selecionado e não desativa a validação TLS do Windows.",
            false);

    public static OperatorRecommendation AuthenticationNotMapped()
        => new(
            "AUTH",
            "Autenticação ainda não mapeada",
            "O endpoint e o formato de login desta firmware não foram homologados. O aplicativo não envia usuário nem senha e não inventa URLs de autenticação.",
            false);

    public static OperatorRecommendation ReadOnlyMode()
        => new(
            "RO",
            "Modo laboratório — somente leitura",
            "Nenhuma alteração de WAN, VLAN, PPPoE, TR-069, firmware ou reset será enviada nesta fase.",
            false);
}
