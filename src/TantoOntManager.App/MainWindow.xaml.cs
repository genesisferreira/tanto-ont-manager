using System.Windows;
using System.Windows.Controls;
using TantoOntManager.App.Observation;
using TantoOntManager.App.ViewModels;

namespace TantoOntManager.App;

public partial class MainWindow : Window
{
    private ObservationWindow? _observationWindow;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.ClearPasswordRequested += (_, _) => PasswordInput.Clear();
        viewModel.ObservationWindowRequested += OnObservationRequested;
        viewModel.ObservationMustStop += (_, _) => CloseObservationWindow();
        Closed += (_, _) =>
        {
            CloseObservationWindow();
            viewModel.ClearSecrets();
        };
    }

    private void OnObservationRequested(object? sender, ObservationLaunchRequest request)
    {
        if (DataContext is not MainViewModel viewModel)
        {
            return;
        }

        var confirm = MessageBox.Show(
            this,
            "Abrir o WebView2 isolado para observar GET/HEAD da interface oficial da ONT?"
            + Environment.NewLine + Environment.NewLine
            + "Somente GET/HEAD no IP selecionado. POST, PUT, PATCH, DELETE, Apply/Save e outros hosts serão bloqueados antes da rede."
            + Environment.NewLine
            + "A captura de gravação WAN/PPPoE, se iniciada, intercepta o primeiro candidato e cancela o envio."
            + Environment.NewLine
            + "Navegue manualmente: Management & Diagnosis → Status; Internet → PON Information; Internet → Status → WAN; Internet → WAN."
            + Environment.NewLine
            + "A senha não será copiada nem registrada.",
            "Confirmar observação GET",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes)
        {
            viewModel.DeclineObservation();
            return;
        }

        CloseObservationWindow();
        var store = viewModel.ObservationSession;
        if (store.Engine is null)
        {
            return;
        }

        _observationWindow = new ObservationWindow(
            store.Engine,
            store,
            request,
            viewModel.ExportWriteContract,
            viewModel.PromoteWriteContract) { Owner = this };
        _observationWindow.InitializationFailed += (_, result) => viewModel.ReportObserverInitializationFailure(result);
        _observationWindow.WriteCaptureIncompatible += (_, message) => viewModel.HandleWriteCaptureIncompatible(message);
        _observationWindow.Closed += (_, _) =>
        {
            _observationWindow = null;
            viewModel.RefreshObservationPanel();
        };
        _observationWindow.Show();
    }

    private void CloseObservationWindow()
    {
        if (_observationWindow is null)
        {
            return;
        }

        try
        {
            _observationWindow.Close();
        }
        catch (Exception)
        {
            // já fechada
        }

        _observationWindow = null;
    }

    private void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel viewModel && sender is PasswordBox box)
        {
            viewModel.SetPassword(box.SecurePassword);
        }
    }
}
