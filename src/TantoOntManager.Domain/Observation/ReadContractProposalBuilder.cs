using TantoOntManager.Domain.Devices;

namespace TantoOntManager.Domain.Observation;

public static class ReadContractProposalBuilder
{
    public static IReadOnlyList<ReadContractProposal> FromObservation(
        IEnumerable<ObservedGetRecord> gets,
        IEnumerable<ResponseStructure> structures,
        FirmwareCompatibility firmwareCompatibility,
        string? firmwareVersion)
    {
        var structureByUrl = structures
            .GroupBy(item => item.NormalizedUrl, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Last(), StringComparer.OrdinalIgnoreCase);
        var unconfirmed = firmwareCompatibility == FirmwareCompatibility.Unconfirmed;
        var firmwareStatus = firmwareCompatibility.ToString();
        var firmwareTarget = string.IsNullOrWhiteSpace(firmwareVersion) ? "Unconfirmed" : firmwareVersion;
        var proposals = new List<ReadContractProposal>();
        foreach (var record in gets.Where(item =>
                     item.Classification == ObservedGetClassification.DataEndpoint && item.IsNewOrChanged))
        {
            structureByUrl.TryGetValue(record.NormalizedUrl, out var structure);
            var fields = structure?.Keys.Concat(structure.FieldIds).Concat(structure.ColumnNames).Distinct().ToList()
                         ?? [];
            var extras = record.ExtraParameterNames;
            var required = extras.Where(name => !LooksVariable(name)).ToList();
            var variable = extras.Where(LooksVariable).ToList();
            proposals.Add(new ReadContractProposal(
                firmwareTarget,
                firmwareStatus,
                record.Screen,
                record.Path,
                record.Type,
                record.Tag,
                required,
                variable,
                structure?.Format ?? "desconhecido",
                fields,
                $"GET observado na tela {record.Screen.ToOperatorLabel()} status={record.StatusCode} hash={record.Sha256[..Math.Min(12, record.Sha256.Length)]}",
                unconfirmed
                    ? "Firmware Unconfirmed; escrita proibida. Contrato ainda não homologado no adaptador."
                    : "Somente leitura. Não entra na allowlist permanente sem revisão humana.",
                RecommendParser(record, structure),
                WriteForbidden: true));
        }

        return proposals;
    }

    private static bool LooksVariable(string name)
        => name.Contains("token", StringComparison.OrdinalIgnoreCase)
           || name.Contains("random", StringComparison.OrdinalIgnoreCase)
           || name.Contains("nonce", StringComparison.OrdinalIgnoreCase)
           || name.Contains("_", StringComparison.Ordinal) && name.Contains("id", StringComparison.OrdinalIgnoreCase);

    private static string RecommendParser(ObservedGetRecord record, ResponseStructure? structure)
    {
        if (structure is null)
        {
            return "Revisar o GET observado; sem estrutura sanitizada suficiente para propor parser.";
        }

        if (structure.Format == "json")
        {
            return "Parser JSON por chaves literais observadas; mascarar serial/MAC/LOID/PPPoE.";
        }

        if (structure.Format.StartsWith("html", StringComparison.OrdinalIgnoreCase))
        {
            return "Parser estrutural por id/name e colunas de tabela; não concatenar texto do pai.";
        }

        return "Associar campos por Transfer_meaning ou atribuições JS literais; não inventar tags.";
    }
}
