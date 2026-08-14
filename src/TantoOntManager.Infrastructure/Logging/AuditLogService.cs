using Microsoft.Extensions.Logging;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Audit;

namespace TantoOntManager.Infrastructure.Logging;

public sealed class AuditLogService : IAuditLogService
{
    private readonly ILogger<AuditLogService> _logger;

    public AuditLogService(ILogger<AuditLogService> logger)
    {
        _logger = logger;
    }

    public void Record(AuditEvent auditEvent)
    {
        _logger.LogInformation(
            "Auditoria action={Action} outcome={Outcome} target={Target} details={Details}",
            auditEvent.Action,
            auditEvent.Outcome,
            auditEvent.TargetAddress,
            auditEvent.Details);
    }
}
