namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BV9310P8N1WriteAllowlist
{
    public static IReadOnlyList<string> Endpoints { get; } = [];

    public static bool Allows(string method, string path)
        => false;

    public static bool IsEmpty => Endpoints.Count == 0;
}
