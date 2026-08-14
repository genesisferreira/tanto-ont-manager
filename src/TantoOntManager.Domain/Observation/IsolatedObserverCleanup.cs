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
            TryDeleteEmptyObserverParent(folder);
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

    private static void TryDeleteEmptyObserverParent(string folder)
    {
        try
        {
            var parent = Directory.GetParent(folder);
            if (parent is null
                || !parent.Exists
                || !string.Equals(parent.Name, "observer-webview", StringComparison.OrdinalIgnoreCase)
                || parent.EnumerateFileSystemInfos().Any())
            {
                return;
            }

            parent.Delete(false);
        }
        catch (IOException)
        {
            // pasta pai ainda em uso
        }
        catch (UnauthorizedAccessException)
        {
            // melhor esforço
        }
    }
}
