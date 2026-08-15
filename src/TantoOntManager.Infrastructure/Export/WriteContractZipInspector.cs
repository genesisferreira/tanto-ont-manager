using System.IO.Compression;
using System.Text;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.Infrastructure.Export;

public static class WriteContractZipInspector
{
    public static ObservationZipInspection Inspect(string zipPath)
    {
        using var zip = ZipFile.OpenRead(zipPath);
        var names = zip.Entries.Select(entry => entry.Name).ToList();
        var combined = new StringBuilder();
        foreach (var entry in zip.Entries)
        {
            using var stream = entry.Open();
            using var reader = new StreamReader(stream, Encoding.UTF8);
            combined.AppendLine(reader.ReadToEnd());
        }

        return WriteContractContentInspector.Inspect(combined.ToString(), names);
    }
}
