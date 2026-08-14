namespace TantoOntManager.Domain.Discovery;

public enum AuthenticatedRouteKind
{
    DataEndpoint = 0,
    MenuFolder = 1,
    MenuLeaf = 2,
    HomepageShell = 3,
    ActionEndpoint = 4,
    UnresolvedDynamicRoute = 5
}

public enum RouteConfidence
{
    None = 0,
    Medium = 1,
    High = 2
}
