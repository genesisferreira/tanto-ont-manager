using System.Net;
using TantoOntManager.Domain.Network;

namespace TantoOntManager.Security.Tls;

public sealed class ProbeSessionSettings
{
    public LocalCertificateTrust Trust { get; set; } = LocalCertificateTrust.Denied(IPAddress.None);
}
