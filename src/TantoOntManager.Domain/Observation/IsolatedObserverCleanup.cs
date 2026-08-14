namespace TantoOntManager.Domain.Observation;

public static class IsolatedObserverCleanup
{
    public static bool DestroyUserDataFolder(string? folder)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            return true;
        }

        try
        {
            Directory.Delete(folder, true);
            return !Directory.Exists(folder);
        }
        catch (IOException)
        {
            return !Directory.Exists(folder);
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
}
