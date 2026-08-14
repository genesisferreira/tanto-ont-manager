using System.Net;
using FluentAssertions;
using TantoOntManager.Security.Export;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Domain.Tests;

public sealed class PublicExportSecretScannerTests
{
    [Fact]
    public void Allows_public_html_without_secrets()
    {
        var html = "<html><body>Welcome to F6201B. ZTE Corporation</body></html>";
        var result = PublicExportSecretScanner.Scan(html, [], "operador", "segredo-lab");
        result.Blocked.Should().BeFalse();
    }

    [Fact]
    public void Blocks_when_typed_password_appears_in_html()
    {
        var html = "<html><body>segredo-lab leaked</body></html>";
        var result = PublicExportSecretScanner.Scan(html, [], null, "segredo-lab");
        result.Blocked.Should().BeTrue();
        result.Reasons.Should().NotBeEmpty();
    }

    [Fact]
    public void Blocks_cookie_header()
    {
        var result = PublicExportSecretScanner.Scan("<html></html>", ["Set-Cookie: a=b"], null, null);
        result.Blocked.Should().BeTrue();
    }
}

public sealed class LocalCertificateSelectedEndpointTests
{
    [Fact]
    public void Accepts_self_signed_only_for_selected_ip_when_certificate_exists()
    {
        var trust = LocalCertificateTrust.ForSelectedEndpoint(IPAddress.Parse("192.168.100.1"));
        using var cert = CreateEphemeralCertificate();
        LocalEndpointCertificatePolicy.Validate(
            trust,
            IPAddress.Parse("192.168.100.1"),
            System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors,
            cert).Should().BeTrue();

        LocalEndpointCertificatePolicy.Validate(
            trust,
            IPAddress.Parse("10.0.0.1"),
            System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors,
            cert).Should().BeFalse();
    }

    private static System.Security.Cryptography.X509Certificates.X509Certificate2 CreateEphemeralCertificate()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=192.168.100.1",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
