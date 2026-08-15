using System.Text;
using System.Text.RegularExpressions;
using TantoOntManager.Domain.Devices;

namespace TantoOntManager.Domain.Observation;

public static class WriteCapabilityClassifier
{
    public static WriteCapabilityReport Evaluate(WriteCapabilityFacts facts)
    {
        var evidences = new List<WriteCapabilityEvidence>();
        var ipTypes = facts.IpTypeOptions.Where(WriteCapabilityTokenScanner.IsPublicEnumeration).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var types = facts.TypeOptions.Where(WriteCapabilityTokenScanner.IsPublicEnumeration).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var linkTypes = facts.LinkTypeOptions.Where(WriteCapabilityTokenScanner.IsPublicEnumeration).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var allOptions = ipTypes.Concat(types).Concat(linkTypes).ToList();
        var buttonTexts = facts.Controls.Select(item => item.ButtonText).Where(text => !string.IsNullOrWhiteSpace(text)).ToList();
        var handlers = facts.Controls.Select(item => item.HandlerName).Where(text => !string.IsNullOrWhiteSpace(text)).ToList();
        var menu = facts.MenuLeaves.Where(item => !string.IsNullOrWhiteSpace(item)).ToList();
        var profiles = facts.WanProfiles.Where(item => !string.IsNullOrWhiteSpace(item)).ToList();

        if (facts.Firmware == FirmwareCompatibility.ConfirmedCompatible
            && string.Equals(facts.SoftwareVersion, WriteCaptureEligibility.ExpectedSoftware, StringComparison.Ordinal))
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.FIRMWARE_CONFIRMED",
                "Firmware confirmada: " + facts.SoftwareVersion,
                "session"));
        }

        if (facts.WanPageObserved)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.WAN_PAGE_OBSERVED",
                "Página WAN observada nesta sessão.",
                "navigation"));
        }

        if (facts.PageScrolledToFooter)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.FOOTER_REACHED",
                "A página foi percorrida até o rodapé.",
                "dom"));
        }

        if (profiles.Count > 0)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.PROFILES_VISIBLE",
                "Perfis WAN visíveis: " + string.Join(", ", profiles),
                "session"));
        }

        if (ipTypes.Count > 0)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.IPTYPE_OPTIONS",
                "IP Type oferece: " + string.Join(", ", ipTypes),
                "dom"));
        }

        var pppoeInOptions = allOptions.Any(WriteCapabilityTokenScanner.LooksLikePppoe);
        var pppoeInButtons = buttonTexts.Any(WriteCapabilityTokenScanner.LooksLikePppoe);
        var createInUi = buttonTexts.Concat(menu).Concat(handlers).Any(WriteCapabilityTokenScanner.LooksLikeCreate)
                         || facts.Controls.Any(item => WriteCapabilityTokenScanner.LooksLikeCreate(item.Name)
                                                       || WriteCapabilityTokenScanner.LooksLikeCreate(item.Id));
        var applyInUi = buttonTexts.Concat(handlers).Any(WriteCapabilityTokenScanner.LooksLikeApplySave)
                        || facts.Controls.Any(item => WriteCapabilityTokenScanner.LooksLikeApplySave(item.Name)
                                                      || WriteCapabilityTokenScanner.LooksLikeApplySave(item.Id)
                                                      || WriteCapabilityTokenScanner.LooksLikeApplySave(item.ButtonText));

        var pppoe = pppoeInOptions || pppoeInButtons
            ? WriteCapabilityAvailability.Available
            : SelectAvailability(facts.WanPageObserved && (ipTypes.Count > 0 || types.Count > 0 || facts.PageScrolledToFooter));
        var create = createInUi
            ? WriteCapabilityAvailability.Available
            : SelectAvailability(facts.WanPageObserved && facts.PageScrolledToFooter);
        var apply = applyInUi
            ? WriteCapabilityAvailability.Available
            : SelectAvailability(facts.WanPageObserved && facts.PageScrolledToFooter);

        if (pppoe == WriteCapabilityAvailability.Unavailable)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.PPPOE_ABSENT",
                "PPPoE não aparece nas opções Type / Link Type / IP Type nem em botões.",
                "dom"));
        }
        else if (pppoe == WriteCapabilityAvailability.Available)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.PPPOE_PRESENT",
                "Opção PPPoE observada na interface.",
                "dom"));
        }

        if (create == WriteCapabilityAvailability.Unavailable)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.CREATE_ABSENT",
                "Create New Item / Add / New WAN não foram encontrados após percorrer a página.",
                "dom"));
        }
        else if (create == WriteCapabilityAvailability.Available)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.CREATE_PRESENT",
                "Controle de criação de perfil observado.",
                "dom"));
        }

        if (apply == WriteCapabilityAvailability.Unavailable)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.APPLY_SAVE_ABSENT",
                "Apply/Save não foram encontrados após percorrer a página.",
                "dom"));
        }
        else if (apply == WriteCapabilityAvailability.Available)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.APPLY_SAVE_PRESENT",
                "Apply/Save observado na interface.",
                "dom"));
        }

        var blocked = facts.Controls
            .Where(item => (item.Disabled || item.ReadOnly || item.Hidden) && !item.Sensitive)
            .Select(item => string.Join(":", new[] { item.Tag, item.Name ?? item.Id ?? item.Type }.Where(part => !string.IsNullOrWhiteSpace(part))))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (blocked.Count > 0)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.DISABLED_READONLY_HIDDEN",
                "Controles disabled/readonly/hidden: " + string.Join(", ", blocked.Take(12)),
                "dom"));
        }

        var menuHasWrite = menu.Any(item => WriteCapabilityTokenScanner.LooksLikeCreate(item)
                                            || WriteCapabilityTokenScanner.LooksLikeApplySave(item)
                                            || WriteCapabilityTokenScanner.LooksLikePppoe(item));
        if (menu.Count > 0 && !menuHasWrite)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.MENU_WITHOUT_WRITE_LEAVES",
                "menuTreeJSON não lista folhas de criação/gravação PPPoE.",
                "menu"));
        }

        var isolatedMissingButton = !facts.PageScrolledToFooter
                                    && ipTypes.Count == 0
                                    && apply == WriteCapabilityAvailability.Unconfirmed
                                    && create == WriteCapabilityAvailability.Unconfirmed;
        if (isolatedMissingButton)
        {
            evidences.Add(new WriteCapabilityEvidence(
                "EVID.ISOLATED_ABSENCE_NOT_CONCLUSIVE",
                "A ausência isolada de um botão não é conclusão definitiva.",
                "policy"));
        }

        var conclusion = Conclude(
            pppoe,
            create,
            apply,
            facts,
            ipTypes,
            blocked.Count,
            menu.Count,
            menuHasWrite,
            isolatedMissingButton,
            profiles);
        var (message, next) = Messages(conclusion);
        return new WriteCapabilityReport(
            facts.Manufacturer,
            facts.Model,
            facts.SoftwareVersion,
            facts.Firmware,
            MaskUsername(facts.ObservedUsername),
            menu,
            profiles,
            types,
            linkTypes,
            ipTypes,
            blocked,
            evidences,
            pppoe,
            create,
            apply,
            conclusion,
            message,
            next,
            facts.PageScrolledToFooter,
            facts.WanPageObserved,
            facts.WriteCandidatesIntercepted,
            0);
    }

    public static string ToOperatorText(WriteCapabilityReport report)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Conta observada: " + (report.ObservedUsername ?? "—"));
        builder.AppendLine("Firmware confirmada: " + FirmwareLabel(report));
        builder.AppendLine("Perfis WAN encontrados: " + JoinOrDash(report.WanProfiles));
        builder.AppendLine("Tipos de conexão disponíveis: " + JoinOrDash(report.IpTypeOptions.Concat(report.TypeOptions).Concat(report.LinkTypeOptions).Distinct(StringComparer.OrdinalIgnoreCase)));
        builder.AppendLine("PPPoE disponível: " + WriteCapabilityReport.AvailabilityLabel(report.PppoeAvailable));
        builder.AppendLine("Criar perfil disponível: " + WriteCapabilityReport.AvailabilityLabel(report.CreateProfileAvailable));
        builder.AppendLine("Apply/Save disponível: " + WriteCapabilityReport.AvailabilityLabel(report.ApplySaveAvailable));
        builder.AppendLine("Controles bloqueados/ocultos: " + JoinOrDash(report.BlockedOrHiddenControls));
        builder.AppendLine("Conclusão: " + report.Conclusion);
        builder.AppendLine("Evidências:");
        foreach (var evidence in report.Evidences)
        {
            builder.AppendLine("- [" + evidence.Code + "] " + evidence.Description);
        }

        builder.AppendLine("Próximo passo recomendado: " + report.NextStep);
        if (report.PppoeAvailable != WriteCapabilityAvailability.Available
            && report.CreateProfileAvailable != WriteCapabilityAvailability.Available
            && report.Conclusion is WriteCapabilityConclusion.PppoeOptionUnavailable
                or WriteCapabilityConclusion.ReadOnlyAccount
                or WriteCapabilityConclusion.PresetLocked)
        {
            builder.AppendLine(WriteCapabilityReport.PppoeUnavailableOperatorMessage);
        }

        builder.AppendLine("Candidatos interceptados: " + report.WriteCandidatesIntercepted);
        builder.AppendLine("Requisições de configuração enviadas: 0");
        return ObservationSanitizer.SanitizeText(builder.ToString());
    }

    private static WriteCapabilityConclusion Conclude(
        WriteCapabilityAvailability pppoe,
        WriteCapabilityAvailability create,
        WriteCapabilityAvailability apply,
        WriteCapabilityFacts facts,
        IReadOnlyList<string> ipTypes,
        int blockedCount,
        int menuCount,
        bool menuHasWrite,
        bool isolatedMissingButton,
        IReadOnlyList<string> profiles)
    {
        if ((pppoe == WriteCapabilityAvailability.Available || create == WriteCapabilityAvailability.Available)
            && apply == WriteCapabilityAvailability.Available)
        {
            return WriteCapabilityConclusion.WriteUiAvailable;
        }

        var ipTypeEnumeratedWithoutPppoe = facts.WanPageObserved
                                           && ipTypes.Count >= 2
                                           && ipTypes.Any(item => item.Equals("DHCP", StringComparison.OrdinalIgnoreCase))
                                           && ipTypes.Any(item => item.Equals("Static", StringComparison.OrdinalIgnoreCase))
                                           && pppoe == WriteCapabilityAvailability.Unavailable
                                           && facts.PageScrolledToFooter;
        if (ipTypeEnumeratedWithoutPppoe)
        {
            return WriteCapabilityConclusion.PppoeOptionUnavailable;
        }

        if (isolatedMissingButton)
        {
            return WriteCapabilityConclusion.InsufficientEvidence;
        }

        var multiPermission = facts.WanPageObserved
                              && facts.PageScrolledToFooter
                              && create == WriteCapabilityAvailability.Unavailable
                              && apply == WriteCapabilityAvailability.Unavailable
                              && blockedCount > 0
                              && menuCount > 0
                              && !menuHasWrite;
        if (multiPermission)
        {
            return WriteCapabilityConclusion.ReadOnlyAccount;
        }

        var preset = profiles.Any(name => Regex.IsMatch(name, "(?i)(HSI_TR069|VOIP_IPTV)"))
                     && facts.WanPageObserved
                     && create == WriteCapabilityAvailability.Unavailable
                     && blockedCount > 0
                     && facts.PageScrolledToFooter;
        if (preset)
        {
            return WriteCapabilityConclusion.PresetLocked;
        }

        return WriteCapabilityConclusion.InsufficientEvidence;
    }

    private static (string Message, string Next) Messages(WriteCapabilityConclusion conclusion)
    {
        return conclusion switch
        {
            WriteCapabilityConclusion.WriteUiAvailable => (
                "A interface expõe controles de gravação. A captura permanece bloqueada antes da rede.",
                "Inicie a captura bloqueada e clique manualmente em Apply/Save na UI oficial."),
            WriteCapabilityConclusion.PppoeOptionUnavailable => (
                WriteCapabilityReport.PppoeUnavailableOperatorMessage,
                "Não promover contrato de gravação. Use credencial oficial de provisionamento ou solicite o contrato autorizado."),
            WriteCapabilityConclusion.ReadOnlyAccount => (
                WriteCapabilityReport.PppoeUnavailableOperatorMessage,
                "A conta aparenta ser somente leitura. Não contornar permissões; use credencial de provisionamento."),
            WriteCapabilityConclusion.PresetLocked => (
                WriteCapabilityReport.PppoeUnavailableOperatorMessage,
                "Os perfis aparentam estar presos ao preset. Não criar WAN nesta conta."),
            _ => (
                "Evidências insuficientes para concluir a capacidade de escrita.",
                "Percorra a página WAN até o rodapé e inspecione a estrutura do DOM.")
        };
    }

    private static WriteCapabilityAvailability SelectAvailability(bool enoughContext)
        => enoughContext ? WriteCapabilityAvailability.Unavailable : WriteCapabilityAvailability.Unconfirmed;

    private static string FirmwareLabel(WriteCapabilityReport report)
        => string.IsNullOrWhiteSpace(report.SoftwareVersion)
            ? report.Firmware.ToString()
            : report.SoftwareVersion + " (" + report.Firmware + ")";

    private static string JoinOrDash(IEnumerable<string> values)
    {
        var list = values.Where(item => !string.IsNullOrWhiteSpace(item)).ToList();
        return list.Count == 0 ? "—" : string.Join(", ", list);
    }

    private static string? MaskUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        if (username.Contains('@', StringComparison.Ordinal) || WriteBodyInspector.IsSensitiveName(username))
        {
            return ObservationSanitizer.MaskFieldValue("username", username);
        }

        return username.Length > 32 ? username[..32] : username;
    }
}
