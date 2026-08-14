using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using TantoOntManager.App.ViewModels;
using TantoOntManager.Infrastructure.DependencyInjection;

namespace TantoOntManager.App;

public partial class App : System.Windows.Application
{
    private ServiceProvider? _services;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var logDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "TantoTelecom",
            "TantoOntManager",
            "logs");

        var services = new ServiceCollection();
        services.AddTantoOntManager(logDirectory);
        services.AddSingleton<MainViewModel>();
        services.AddSingleton<MainWindow>();
        _services = services.BuildServiceProvider();

        var window = _services.GetRequiredService<MainWindow>();
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _services?.Dispose();
        base.OnExit(e);
    }
}
