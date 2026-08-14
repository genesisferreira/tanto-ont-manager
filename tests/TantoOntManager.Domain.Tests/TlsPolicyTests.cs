using System.Net;
using FluentAssertions;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Domain.Tests;

public sealed class LocalCertificatePolicyTests
{
    [Fact]
    public void Rejects_self_signed_when_trust_is_denied()
    {
        var trust = LocalCertificateTrust.Denied(IPAddress.Parse("192.168.100.1"));
        LocalEndpointCertificatePolicy.Validate(
            trust,
            IPAddress.Parse("192.168.100.1"),
            System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors,
            certificate: null).Should().BeFalse();
    }

    [Fact]
    public void Does_not_trust_a_different_ip()
    {
        var trust = LocalCertificateTrust.ForSelectedEndpoint(IPAddress.Parse("192.168.100.1"));
        LocalEndpointCertificatePolicy.Validate(
            trust,
            IPAddress.Parse("192.168.1.1"),
            System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch,
            certificate: null).Should().BeFalse();
    }
}
