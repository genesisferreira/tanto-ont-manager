using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.Infrastructure.Export;

public static class WriteContractExportFinalizer
{
    public static Result<WriteContractExportResult> InspectAndKeepOrDelete(string directory, string zipPath)
    {
        ObservationZipInspection inspection;
        try
        {
            inspection = WriteContractZipInspector.Inspect(zipPath);
        }
        catch (Exception)
        {
            DeleteIncomplete(directory, zipPath);
            return Result.Failure<WriteContractExportResult>(Error.Create(
                ErrorCodes.WriteCaptureExportInspectionFailed,
                "O pacote da proposta foi recusado pela inspeção de sanitização e apagado."));
        }

        if (!inspection.IsAcceptable)
        {
            DeleteIncomplete(directory, zipPath);
            return Result.Failure<WriteContractExportResult>(Error.Create(
                ErrorCodes.WriteCaptureExportInspectionFailed,
                "O pacote da proposta foi recusado pela inspeção de sanitização e apagado."));
        }

        return Result.Success(new WriteContractExportResult(directory, zipPath, inspection));
    }

    public static void DeleteIncomplete(string directory, string zipPath)
    {
        try
        {
            if (File.Exists(zipPath))
            {
                File.Delete(zipPath);
            }
        }
        catch (IOException)
        {
            // melhor esforço
        }

        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, true);
            }
        }
        catch (IOException)
        {
            // melhor esforço
        }
    }
}
