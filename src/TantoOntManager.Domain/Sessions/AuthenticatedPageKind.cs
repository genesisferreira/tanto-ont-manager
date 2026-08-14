namespace TantoOntManager.Domain.Sessions;

public enum AuthenticatedPageKind
{
    AuthenticatedPage = 0,
    PublicLoginPage = 1,
    SessionExpiredEvidence = 2,
    UnexpectedPage = 3
}
