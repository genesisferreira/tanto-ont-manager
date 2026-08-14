using System.Collections.ObjectModel;
using System.Net;
using System.Reflection;
using System.Security;
using System.Windows.Input;
using TantoOntManager.Application.UseCases;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Network;
using TantoOntManager.Infrastructure.DependencyInjection;

namespace TantoOntManager.App.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    public const string KnownIp100 = "192.168.100.1";
    public const string KnownIp1 = "192.168.1.1";
    public const string CustomIpLabel = "Personalizado";

    private readonly IListEthernetAdaptersUseCase _listAdapters;
    private readonly IDetectOntUseCase _detectOnt;
    private readonly ITestConnectionUseCase _testConnection;
    private readonly IAuthenticateDeviceUseCase _authenticate;
    private readonly LoggingPaths _loggingPaths;
    private CancellationTokenSource _cts = new();

    private EthernetAdapterInfo? _selectedAdapter;
    private string _selectedKnownIp = KnownIp100;
    private string _customIp = string.Empty;
    private string _username = string.Empty;
    private bool _doNotPersistCredential = true;
    private bool _trustLocalCertificate = true;
    private bool _isBusy;
    private string _lastOperation = "Nenhuma operação executada";
    private string _lastDuration = "—";
    private string _statusLabel = ApplicationStatus.Disconnected.ToUiLabel();
    private ApplicationStatus _status = ApplicationStatus.Disconnected;
    private string _manufacturer = "—";
    private string _model = "—";
    private string _hardware = "—";
    private string _firmware = "—";
    private string _boot = "—";
    private string _serial = "—";
    private string _mac = "—";
    private string _pon = "—";
    private string _temperature = "—";
    private string _opticalPower = "—";
    private string _wanProfiles = "—";
    private string _capabilities = "—";
    private string _recommendations = "Modo laboratório — somente leitura. Nenhuma alteração será enviada à ONT ou à placa de rede.";
    private string _authMessage = "O login desta firmware ainda não foi mapeado. Usuário e senha não serão enviados.";
    private AdapterProbeSnapshot? _lastProbe;

    public MainViewModel(
        IListEthernetAdaptersUseCase listAdapters,
        IDetectOntUseCase detectOnt,
        ITestConnectionUseCase testConnection,
        IAuthenticateDeviceUseCase authenticate,
        LoggingPaths loggingPaths)
    {
        _listAdapters = listAdapters;
        _detectOnt = detectOnt;
        _testConnection = testConnection;
        _authenticate = authenticate;
        _loggingPaths = loggingPaths;

        Adapters = new ObservableCollection<EthernetAdapterInfo>();
        KnownIpOptions = new ObservableCollection<string> { KnownIp100, KnownIp1, CustomIpLabel };
        DetectCommand = new RelayCommand(DetectAsync, () => !IsBusy);
        TestConnectionCommand = new RelayCommand(TestConnectionAsync, () => !IsBusy);
        RefreshAdaptersCommand = new RelayCommand(LoadAdapters, () => !IsBusy);
        LoginCommand = new RelayCommand(LoginAsync, () => !IsBusy);
        LoadAdapters();
    }

    public ObservableCollection<EthernetAdapterInfo> Adapters { get; }
    public ObservableCollection<string> KnownIpOptions { get; }
    public ICommand DetectCommand { get; }
    public ICommand TestConnectionCommand { get; }
    public ICommand RefreshAdaptersCommand { get; }
    public ICommand LoginCommand { get; }

    public string ProductName => "Tanto ONT Manager";
    public string ModeLabel => OperationMode.LaboratoryReadOnly.ToUiLabel();
    public string VersionLabel => "v" + (Assembly.GetExecutingAssembly()
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.1.0-lab");

    public string LogPath => _loggingPaths.CurrentHint;

    public EthernetAdapterInfo? SelectedAdapter
    {
        get => _selectedAdapter;
        set
        {
            if (SetProperty(ref _selectedAdapter, value))
            {
                RaisePropertyChanged(nameof(LinkState));
                RaisePropertyChanged(nameof(CurrentIpv4));
            }
        }
    }

    public string SelectedKnownIp
    {
        get => _selectedKnownIp;
        set
        {
            if (SetProperty(ref _selectedKnownIp, value))
            {
                RaisePropertyChanged(nameof(IsCustomIp));
                RaisePropertyChanged(nameof(ExpectedOntIp));
            }
        }
    }

    public string CustomIp
    {
        get => _customIp;
        set
        {
            if (SetProperty(ref _customIp, value))
            {
                RaisePropertyChanged(nameof(ExpectedOntIp));
            }
        }
    }

    public bool IsCustomIp => SelectedKnownIp == CustomIpLabel;
    public string ExpectedOntIp => ResolveTargetText();
    public string LinkState => SelectedAdapter?.LinkDisplay ?? "Nenhuma interface selecionada";
    public string CurrentIpv4 => SelectedAdapter?.Ipv4Display ?? "—";

    public string Username
    {
        get => _username;
        set => SetProperty(ref _username, value);
    }

    public bool DoNotPersistCredential
    {
        get => _doNotPersistCredential;
        set => SetProperty(ref _doNotPersistCredential, value);
    }

    public bool TrustLocalCertificate
    {
        get => _trustLocalCertificate;
        set => SetProperty(ref _trustLocalCertificate, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
            {
                (DetectCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (TestConnectionCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (RefreshAdaptersCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (LoginCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public string LastOperation { get => _lastOperation; set => SetProperty(ref _lastOperation, value); }
    public string LastDuration { get => _lastDuration; set => SetProperty(ref _lastDuration, value); }
    public string StatusLabel { get => _statusLabel; set => SetProperty(ref _statusLabel, value); }
    public ApplicationStatus Status { get => _status; set => SetProperty(ref _status, value); }
    public string Manufacturer { get => _manufacturer; set => SetProperty(ref _manufacturer, value); }
    public string Model { get => _model; set => SetProperty(ref _model, value); }
    public string Hardware { get => _hardware; set => SetProperty(ref _hardware, value); }
    public string Firmware { get => _firmware; set => SetProperty(ref _firmware, value); }
    public string Boot { get => _boot; set => SetProperty(ref _boot, value); }
    public string Serial { get => _serial; set => SetProperty(ref _serial, value); }
    public string Mac { get => _mac; set => SetProperty(ref _mac, value); }
    public string Pon { get => _pon; set => SetProperty(ref _pon, value); }
    public string Temperature { get => _temperature; set => SetProperty(ref _temperature, value); }
    public string OpticalPower { get => _opticalPower; set => SetProperty(ref _opticalPower, value); }
    public string WanProfiles { get => _wanProfiles; set => SetProperty(ref _wanProfiles, value); }
    public string Capabilities { get => _capabilities; set => SetProperty(ref _capabilities, value); }
    public string Recommendations { get => _recommendations; set => SetProperty(ref _recommendations, value); }
    public string AuthMessage { get => _authMessage; set => SetProperty(ref _authMessage, value); }

    public SecureString Password { get; private set; } = new();

    public void SetPassword(SecureString password)
    {
        Password.Dispose();
        Password = password.Copy();
    }

    public void LoadAdapters()
    {
        Adapters.Clear();
        foreach (var adapter in _listAdapters.Execute())
        {
            Adapters.Add(adapter);
        }

        SelectedAdapter = Adapters.FirstOrDefault(item => item.HasPhysicalLink) ?? Adapters.FirstOrDefault();
        LastOperation = "Interfaces Ethernet atualizadas";
        LastDuration = "—";
    }

    private async Task DetectAsync()
    {
        if (!TryGetTarget(out var target, out var error))
        {
            SetFailure(error);
            return;
        }

        await RunBusyAsync("Detectar ONT", async () =>
        {
            var report = await _detectOnt.ExecuteAsync(
                new DetectOntCommand(SelectedAdapter, target, TrustLocalCertificate),
                _cts.Token);

            Status = report.Status;
            StatusLabel = report.Status.ToUiLabel();
            LastDuration = FormatDuration(report.Duration);
            Recommendations = string.Join(Environment.NewLine + Environment.NewLine, report.Recommendations.Select(item => $"{item.Title}{Environment.NewLine}{item.Details}"));

            if (report.Device is { } device)
            {
                Manufacturer = device.Identity.Manufacturer;
                Model = device.Identity.Model ?? "Não confirmado";
                Hardware = device.Identity.Firmware.HardwareDisplay;
                Firmware = device.Identity.Firmware.SoftwareDisplay;
                Boot = device.Identity.Firmware.BootDisplay;
                Serial = SensitiveDataMasker.MaskSerial(device.Identity.SerialNumber);
                Mac = SensitiveDataMasker.MaskMac(device.Identity.MacAddress);
                _lastProbe = new AdapterProbeSnapshot(
                    device.AdapterId,
                    device.Identity.Manufacturer,
                    device.Identity.Model,
                    device.Endpoint,
                    device.Confidence);
            }
            else
            {
                ClearIdentity("Não identificado");
                _lastProbe = null;
            }

            if (report.PublicDiagnostics is { } diagnostics)
            {
                Pon = diagnostics.Pon.OnuState ?? diagnostics.Pon.Description ?? "—";
                Temperature = diagnostics.Optical.Temperature ?? "Não disponível na interface pública";
                OpticalPower = FormatOptical(diagnostics.Optical);
                WanProfiles = diagnostics.WanProfiles.Count == 0
                    ? diagnostics.AvailabilityNote
                    : string.Join(Environment.NewLine, diagnostics.WanProfiles.Select(profile => profile.Summary));
            }

            Capabilities = report.Capabilities is null
                ? "—"
                : string.Join(Environment.NewLine, report.Capabilities.Notes);

            if (report.Connectivity is { } connectivity)
            {
                LastOperation = $"Detecção em {target}: HTTPS={(connectivity.HttpsReachable ? "sim" : "não")}, HTTP={(connectivity.HttpReachable ? "sim" : "não")}, ICMP={(connectivity.IcmpReachable ? "sim" : "não")}";
            }
        });
    }

    private async Task TestConnectionAsync()
    {
        if (!TryGetTarget(out var target, out var error))
        {
            SetFailure(error);
            return;
        }

        await RunBusyAsync("Testar conexão", async () =>
        {
            var result = await _testConnection.ExecuteAsync(
                new TestConnectionCommand(SelectedAdapter, target, TrustLocalCertificate),
                _cts.Token);

            LastDuration = FormatDuration(result.Duration);
            Status = result.AnyHttpReachable ? ApplicationStatus.Detected : ApplicationStatus.ControlledFailure;
            StatusLabel = Status.ToUiLabel();
            LastOperation = $"Teste {target}: ICMP={(result.IcmpReachable ? "sim" : "não")} HTTPS={(result.HttpsReachable ? "sim" : "não")} HTTP={(result.HttpReachable ? "sim" : "não")} título={result.PageTitle ?? "—"}";
            Recommendations = result.ErrorMessage
                ?? result.TlsNote
                ?? "A interface web respondeu. Nenhuma alteração foi enviada.";

            if (SelectedAdapter?.Ipv4 is { } ipv4 && !ipv4.IsInSameSubnet(target))
            {
                var suggestion = SubnetSuggestion.ForTarget(target);
                if (suggestion is not null)
                {
                    Recommendations = suggestion.ToOperatorText() + Environment.NewLine + Environment.NewLine + Recommendations;
                }
            }
        });
    }

    private async Task LoginAsync()
    {
        if (_lastProbe is null)
        {
            SetFailure("Detecte a ONT antes de tentar autenticar. Sem probe público, o login não é enviado.");
            return;
        }

        await RunBusyAsync("Login", async () =>
        {
            using var credentials = new Domain.Sessions.DeviceCredentials(Username, Password.Copy(), persistRequested: !DoNotPersistCredential);
            var probe = new Domain.Adapters.AdapterProbeResult
            {
                Matched = true,
                AdapterId = _lastProbe.AdapterId,
                Manufacturer = _lastProbe.Manufacturer,
                Model = _lastProbe.Model,
                Confidence = _lastProbe.Confidence,
                Endpoint = _lastProbe.Endpoint
            };

            var result = await _authenticate.ExecuteAsync(
                new AuthenticateCommand(_lastProbe.Endpoint, probe, credentials),
                _cts.Token);

            AuthMessage = result.Error?.Message + Environment.NewLine + result.Error?.Recommendation;
            Status = ApplicationStatus.ControlledFailure;
            StatusLabel = result.Outcome.ToString() == "MethodNotMapped"
                ? "AuthenticationMethodNotMapped"
                : ApplicationStatus.ControlledFailure.ToUiLabel();
            LastOperation = "Login não enviado: método de autenticação não mapeado para esta firmware.";
        });
    }

    private async Task RunBusyAsync(string operation, Func<Task> action)
    {
        IsBusy = true;
        _cts.Cancel();
        _cts.Dispose();
        _cts = new CancellationTokenSource();
        var started = DateTimeOffset.UtcNow;
        try
        {
            await action();
        }
        catch (OperationCanceledException)
        {
            SetFailure("Operação cancelada.");
        }
        catch (InvalidOperationException ex)
        {
            SetFailure(ex.Message);
        }
        finally
        {
            LastDuration = FormatDuration(DateTimeOffset.UtcNow - started);
            if (string.IsNullOrWhiteSpace(LastOperation) || LastOperation == "Nenhuma operação executada")
            {
                LastOperation = operation;
            }

            IsBusy = false;
        }
    }

    private bool TryGetTarget(out IPAddress target, out string error)
    {
        target = IPAddress.None;
        error = string.Empty;
        var text = ResolveTargetText();
        if (!IPAddress.TryParse(text, out target!))
        {
            error = "Informe um IPv4 válido. A detecção não varre a rede; somente IPs permitidos ou o IP personalizado informado.";
            return false;
        }

        IPAddress? custom = SelectedKnownIp == CustomIpLabel ? target : null;
        if (!KnownOntAddresses.IsKnownOrExplicitlyProvided(target, custom))
        {
            error = "Somente 192.168.100.1, 192.168.1.1 ou um IP personalizado informado pelo operador podem ser testados.";
            return false;
        }

        return true;
    }

    private string ResolveTargetText()
        => SelectedKnownIp == CustomIpLabel
            ? CustomIp.Trim()
            : SelectedKnownIp;

    private void SetFailure(string message)
    {
        Status = ApplicationStatus.ControlledFailure;
        StatusLabel = ApplicationStatus.ControlledFailure.ToUiLabel();
        LastOperation = message;
        Recommendations = message;
    }

    private void ClearIdentity(string fallback)
    {
        Manufacturer = fallback;
        Model = fallback;
        Hardware = "—";
        Firmware = "—";
        Boot = "—";
        Serial = "—";
        Mac = "—";
        Pon = "—";
        Temperature = "—";
        OpticalPower = "—";
        WanProfiles = "—";
        Capabilities = "—";
    }

    private static string FormatDuration(TimeSpan duration)
        => duration.TotalSeconds < 1
            ? $"{duration.TotalMilliseconds:0} ms"
            : $"{duration.TotalSeconds:0.0} s";

    private static string FormatOptical(Domain.Devices.OpticalReading optical)
    {
        if (optical.TxPower is null && optical.RxPower is null)
        {
            return "Não disponível na interface pública";
        }

        return $"Tx {optical.TxPower ?? "—"} / Rx {optical.RxPower ?? "—"}";
    }

    private sealed record AdapterProbeSnapshot(
        string AdapterId,
        string Manufacturer,
        string? Model,
        OntEndpoint Endpoint,
        double Confidence);
}
