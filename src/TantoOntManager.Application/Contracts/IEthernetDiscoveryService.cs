using TantoOntManager.Domain.Network;

namespace TantoOntManager.Application.Contracts;

public interface IEthernetDiscoveryService
{
    IReadOnlyList<EthernetAdapterInfo> ListEthernetAdapters();
}
