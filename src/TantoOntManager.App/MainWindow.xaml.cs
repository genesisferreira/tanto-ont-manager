using System.Windows;
using System.Windows.Controls;
using TantoOntManager.App.ViewModels;

namespace TantoOntManager.App;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.ClearPasswordRequested += (_, _) => PasswordInput.Clear();
        Closed += (_, _) => viewModel.ClearSecrets();
    }

    private void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel viewModel && sender is PasswordBox box)
        {
            viewModel.SetPassword(box.SecurePassword);
        }
    }
}
