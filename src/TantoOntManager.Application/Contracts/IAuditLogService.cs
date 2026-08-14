using TantoOntManager.Domain.Audit;

namespace TantoOntManager.Application.Contracts;

public interface IAuditLogService
{
    void Record(AuditEvent auditEvent);
}
