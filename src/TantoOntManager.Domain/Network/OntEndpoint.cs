using System.Net;

namespace TantoOntManager.Domain.Network;

public sealed record OntEndpoint
{
    public IPAddress Address { get; }
    public string Scheme { get; }
    public int Port { get; }

    private OntEndpoint(IPAddress address, string scheme, int port)
    {
        Address = address;
        Scheme = scheme;
        Port = port;
    }

    public Uri BaseUri => new($"{Scheme}://{Address}:{Port}/", UriKind.Absolute);

    public static OntEndpoint Https(IPAddress address, int port = 443)
        => new(address, "https", port);

    public static OntEndpoint Http(IPAddress address, int port = 80)
        => new(address, "http", port);

    public static OntEndpoint Create(IPAddress address, string scheme, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (scheme is not ("http" or "https"))
        {
            throw new ArgumentOutOfRangeException(nameof(scheme), "Somente http e https são permitidos.");
        }

        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        return new OntEndpoint(address, scheme, port);
    }

    public override string ToString() => $"{Scheme}://{Address}:{Port}";
}
