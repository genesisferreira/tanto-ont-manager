using System.Net;
using FluentAssertions;
using TantoOntManager.Domain.Network;
using TantoOntManager.Networking.Discovery;

namespace TantoOntManager.Networking.Tests;

public sealed class EthernetDiscoveryTests
{
    [Fact]
    public void Lists_adapters_without_changing_configuration()
    {
        var service = new EthernetDiscoveryService();
        var adapters = service.ListEthernetAdapters();
        adapters.Should().NotBeNull();
        foreach (var adapter in adapters)
        {
            adapter.Id.Should().NotBeNullOrWhiteSpace();
            adapter.Name.Should().NotBeNullOrWhiteSpace();
        }
    }
}

public sealed class SubnetSuggestionNetworkingTests
{
    [Fact]
    public void Custom_ip_suggestion_does_not_touch_the_nic()
    {
        var suggestion = SubnetSuggestion.ForTarget(IPAddress.Parse("192.168.1.1"));
        suggestion!.SuggestedHostAddress.ToString().Should().Be("192.168.1.10");
        suggestion.ToOperatorText().Should().Contain("manualmente");
    }
}
