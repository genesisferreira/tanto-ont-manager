using System.IO;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TantoOntManager.App.ViewModels;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Observation;
using TantoOntManager.Infrastructure.DependencyInjection;

namespace TantoOntManager.App;

public partial class App : System.Windows.Application
{
    private ServiceProvider? _services;

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        base.OnStartup(e);

        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "TantoTelecom",
            "TantoOntManager");

        var services = new ServiceCollection();
        services.AddTantoOntManager(root);
        services.AddSingleton<MainViewModel>();
        services.AddSingleton<MainWindow>();
        _services = services.BuildServiceProvider();

        var window = _services.GetRequiredService<MainWindow>();
        window.Show();
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        if (!ObserverInitializationGuard.ShouldHandleOnDispatcher(e.Exception))
        {
            return;
        }

        var result = ObserverInitializationGuard.FromException(e.Exception, cookiesTransferred: false);
        var logger = _services?.GetService<ILoggerFactory>()?.CreateLogger("TantoOntManager.App");
        logger?.LogError("Observador WebView2: {Message}", result.SanitizedLog);
        var viewModel = _services?.GetService<MainViewModel>();
        viewModel?.ReportObserverInitializationFailure(result);
        Dispatcher.BeginInvoke(new Action(() => viewModel?.RequestObserverWindowClose()), DispatcherPriority.Background);
        e.Handled = true;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _services?.GetService<MainViewModel>()?.ClearSecrets();
        _services?.GetService<IObservationSessionStore>()?.FinishAndDestroy();
        _services?.GetService<IOntAuthSessionStore>()?.End("aplicativo-fechado");
        _services?.Dispose();
        base.OnExit(e);
    }
}
