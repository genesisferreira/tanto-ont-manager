using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using TantoOntManager.App.ViewModels;
using TantoOntManager.Application.Contracts;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Infrastructure.DependencyInjection;

namespace TantoOntManager.App;

public partial class App : System.Windows.Application
{
    private ServiceProvider? _services;

    protected override void OnStartup(StartupEventArgs e)
    {
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

    protected override void OnExit(ExitEventArgs e)
    {
        _services?.GetService<MainViewModel>()?.ClearSecrets();
        _services?.GetService<IObservationSessionStore>()?.FinishAndDestroy();
        _services?.GetService<IOntAuthSessionStore>()?.End("aplicativo-fechado");
        _services?.Dispose();
        base.OnExit(e);
    }
}
