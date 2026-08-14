namespace TantoOntManager.Domain.Sessions;

public enum AuthSessionState
{
    Unmapped = 0,
    ReadyToAuthenticate = 1,
    Authenticating = 2,
    AuthenticatedReadOnly = 3,
    CredentialRejected = 4,
    ContractIncompatible = 5,
    SessionExpired = 6,
    CertificateChanged = 7,
    ControlledFailure = 8
}

public static class AuthSessionStateDisplay
{
    public static string ToUiLabel(this AuthSessionState state) => state switch
    {
        AuthSessionState.Unmapped => "Não mapeado",
        AuthSessionState.ReadyToAuthenticate => "Pronto para autenticar",
        AuthSessionState.Authenticating => "Autenticando",
        AuthSessionState.AuthenticatedReadOnly => "Autenticado — somente leitura",
        AuthSessionState.CredentialRejected => "Credencial recusada",
        AuthSessionState.ContractIncompatible => "Contrato incompatível",
        AuthSessionState.SessionExpired => "Sessão expirada",
        AuthSessionState.CertificateChanged => "Certificado alterado",
        AuthSessionState.ControlledFailure => "Falha controlada",
        _ => state.ToString()
    };
}
