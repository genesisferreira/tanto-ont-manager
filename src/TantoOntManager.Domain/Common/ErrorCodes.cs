namespace TantoOntManager.Domain.Common;

public static class ErrorCodes
{
    public const string NetworkInterfaceNotFound = "NET.INTERFACE_NOT_FOUND";
    public const string NoPhysicalLink = "NET.NO_PHYSICAL_LINK";
    public const string Ipv4NotAssigned = "NET.IPV4_NOT_ASSIGNED";
    public const string SubnetMismatch = "NET.SUBNET_MISMATCH";
    public const string HostUnreachable = "NET.HOST_UNREACHABLE";
    public const string ProbeTimeout = "NET.PROBE_TIMEOUT";
    public const string TlsRejected = "NET.TLS_REJECTED";
    public const string TlsSelfSignedNotAccepted = "NET.TLS_SELF_SIGNED_NOT_ACCEPTED";
    public const string HttpProbeFailed = "NET.HTTP_PROBE_FAILED";
    public const string InsufficientEvidence = "DET.INSUFFICIENT_EVIDENCE";
    public const string ConflictingEvidence = "DET.CONFLICTING_EVIDENCE";
    public const string ExportBlockedSecret = "SEC.EXPORT_BLOCKED_SECRET";
    public const string AdapterNotApplicable = "DET.ADAPTER_NOT_APPLICABLE";
    public const string AuthenticationMethodNotMapped = "AUTH.METHOD_NOT_MAPPED";
    public const string AuthenticationNotAttempted = "AUTH.NOT_ATTEMPTED";
    public const string CredentialsNotPersisted = "AUTH.CREDENTIALS_NOT_PERSISTED";
    public const string CredentialRejected = "AUTH.CREDENTIAL_REJECTED";
    public const string AuthTokenMissing = "AUTH.TOKEN_MISSING";
    public const string AuthTokenExpired = "AUTH.TOKEN_EXPIRED";
    public const string UnexpectedRedirect = "AUTH.UNEXPECTED_REDIRECT";
    public const string RedirectForeignHost = "AUTH.REDIRECT_FOREIGN_HOST";
    public const string CertificateChanged = "AUTH.CERTIFICATE_CHANGED";
    public const string SessionExpired = "AUTH.SESSION_EXPIRED";
    public const string ContractIncompatible = "AUTH.CONTRACT_INCOMPATIBLE";
    public const string GetNotAllowlisted = "AUTH.GET_NOT_ALLOWLISTED";
    public const string PostNotAllowed = "AUTH.POST_NOT_ALLOWED";
    public const string DestructivePageBlocked = "AUTH.DESTRUCTIVE_PAGE_BLOCKED";
    public const string WriteOperationsDisabled = "SEC.WRITE_DISABLED";
    public const string SanitizationUnproven = "SEC.SANITIZATION_UNPROVEN";
    public const string AuthenticatedExportRequiresSession = "SEC.AUTH_EXPORT_REQUIRES_SESSION";
    public const string OperationCancelled = "APP.CANCELLED";
    public const string PublicPageUnreadable = "DET.PUBLIC_PAGE_UNREADABLE";
    public const string IdentityRequiresAuthentication = "DET.IDENTITY_REQUIRES_AUTH";
    public const string DiagnosticsRequiresAuthentication = "DET.DIAGNOSTICS_REQUIRES_AUTH";
    public const string UnexpectedFailure = "APP.UNEXPECTED_FAILURE";
}
