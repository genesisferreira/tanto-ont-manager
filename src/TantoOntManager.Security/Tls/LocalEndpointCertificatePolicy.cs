using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.Security.Tls;

public sealed record LocalCertificateTrust(bool AcceptSelfSignedForSelectedEndpoint, IPAddress SelectedEndpoint)
{
    public static LocalCertificateTrust Denied(IPAddress selectedEndpoint)
        => new(false, selectedEndpoint);

    public static LocalCertificateTrust ForSelectedEndpoint(IPAddress selectedEndpoint)
        => new(true, selectedEndpoint);
}

public static class LocalEndpointCertificatePolicy
{
    public static bool Validate(
        LocalCertificateTrust trust,
        IPAddress remoteAddress,
        SslPolicyErrors errors,
        X509Certificate? certificate)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        if (!trust.AcceptSelfSignedForSelectedEndpoint)
        {
            return false;
        }

        if (!remoteAddress.Equals(trust.SelectedEndpoint))
        {
            return false;
        }

        return certificate is not null;
    }
}
