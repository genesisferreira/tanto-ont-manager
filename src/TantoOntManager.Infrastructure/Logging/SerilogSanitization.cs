using Serilog.Core;
using Serilog.Events;
using TantoOntManager.Domain.Audit;

namespace TantoOntManager.Infrastructure.Logging;

public sealed class SensitiveDataDestructuringPolicy : IDestructuringPolicy
{
    public bool TryDestructure(
        object value,
        ILogEventPropertyValueFactory propertyValueFactory,
        out LogEventPropertyValue result)
    {
        if (value is string text)
        {
            result = new ScalarValue(SensitiveDataMasker.SanitizeLogText(text));
            return true;
        }

        result = new ScalarValue(null);
        return false;
    }
}

public sealed class SensitiveDataEnricher : ILogEventEnricher
{
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        var template = logEvent.MessageTemplate.Text;
        if (template.Contains("password", StringComparison.OrdinalIgnoreCase)
            || template.Contains("senha", StringComparison.OrdinalIgnoreCase)
            || template.Contains("cookie", StringComparison.OrdinalIgnoreCase)
            || template.Contains("token", StringComparison.OrdinalIgnoreCase)
            || template.Contains("authorization", StringComparison.OrdinalIgnoreCase))
        {
            logEvent.AddOrUpdateProperty(propertyFactory.CreateProperty("SensitiveRedacted", true));
        }
    }
}
