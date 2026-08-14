using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using TantoOntManager.Application.Batch;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Application.UseCases;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte;
using TantoOntManager.Infrastructure.Logging;
using TantoOntManager.Infrastructure.Security;
using TantoOntManager.Networking.Discovery;
using TantoOntManager.Networking.Probing;
using TantoOntManager.Security.Logging;
using TantoOntManager.Security.Secrets;
using TantoOntManager.Security.Tls;

namespace TantoOntManager.Infrastructure.DependencyInjection;

[SupportedOSPlatform("windows")]
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddTantoOntManager(this IServiceCollection services, string logDirectory)
    {
        Directory.CreateDirectory(logDirectory);

        var serilog = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .Enrich.With(new SensitiveDataEnricher())
            .Destructure.With(new SensitiveDataDestructuringPolicy())
            .WriteTo.File(
                path: Path.Combine(logDirectory, "tanto-ont-manager-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                shared: true,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
            .CreateLogger();

        services.AddLogging(builder =>
        {
            builder.ClearProviders();
            builder.AddSerilog(serilog, dispose: true);
        });

        services.AddHttpClient();
        services.AddSingleton(new ProbeSessionSettings());
        services.AddSingleton<LogSanitizer>();
        services.AddSingleton<DpapiSecretProtector>();
        services.AddSingleton<ISecureCredentialStore, NonPersistentCredentialStore>();
        services.AddSingleton<IAuditLogService, AuditLogService>();
        services.AddSingleton<IEthernetDiscoveryService, EthernetDiscoveryService>();
        services.AddSingleton<IConnectivityProbeService, ConnectivityProbeService>();
        services.AddSingleton<IPublicWebReader, HttpPublicWebReader>();
        services.AddSingleton<ZteDeviceAdapter>();
        services.AddSingleton<IOntDeviceAdapter>(sp => sp.GetRequiredService<ZteDeviceAdapter>());
        services.AddSingleton<IOntAuthenticationAdapter>(sp => sp.GetRequiredService<ZteDeviceAdapter>());
        services.AddSingleton<IDetectOntUseCase, DetectOntUseCase>();
        services.AddSingleton<ITestConnectionUseCase, TestConnectionUseCase>();
        services.AddSingleton<IListEthernetAdaptersUseCase, ListEthernetAdaptersUseCase>();
        services.AddSingleton<IAuthenticateDeviceUseCase, AuthenticateDeviceUseCase>();
        services.AddSingleton<IBatchProcessingOrchestrator, DisabledBatchProcessingOrchestrator>();
        services.AddSingleton<IBatchWorkOrderReader, UnsupportedBatchWorkOrderReader>();
        services.AddSingleton(new LoggingPaths(logDirectory));

        return services;
    }
}

public sealed record LoggingPaths(string Directory)
{
    public string CurrentHint => Path.Combine(Directory, "tanto-ont-manager-.log");
}
