using System.Collections.ObjectModel;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows.Input;
using TantoOntManager.App.Observation;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Application.UseCases;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Audit;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Detection;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;
using TantoOntManager.Domain.Observation;
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
    private readonly IExportPublicDiagnosticUseCase _exportDiagnostic;
    private readonly IExportAuthenticatedDiagnosticUseCase _exportAuthenticated;
    private readonly IMapAuthenticatedReadsUseCase _mapReads;
    private readonly IExportAuthenticatedReadMapUseCase _exportReadMap;
    private readonly IExportObservationUseCase _exportObservation;
    private readonly IPromoteReadContractUseCase _promoteContract;
    private readonly IAuthenticateDeviceUseCase _authenticate;
    private readonly IEndAuthenticatedSessionUseCase _endSession;
    private readonly IOntAuthSessionStore _authSession;
    private readonly IObservationSessionStore _observation;
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
    private AuthSessionState _authState = AuthSessionState.Unmapped;
    private DetectionReport? _lastReport;
    private AdapterProbeResult? _lastProbe;
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
    private string _authMessage = "Detecte a F6201B para habilitar o login homologado. A senha da etiqueta é informada manualmente e não é persistida.";
    private string _httpStatus = "—";
    private string _publicTitle = "—";
    private string _responseSize = "—";
    private string _shortHash = "—";
    private string _confidenceLabel = DetectionConfidence.Insufficient.ToUiLabel();
    private string _evidenceText = "Nenhuma evidência pública ainda.";
    private string _probeDetails = "Execute Detectar ONT para preencher o diagnóstico sanitizado.";
    private string _exportPath = "—";
    private bool _detailsExpanded;
    private string _loginPostCount = "0";
    private string _logoutPostCount = "0";
    private string _configPostCount = "0";
    private string _zipInspection = "Exporte o diagnóstico autenticado durante a sessão para inspecionar o ZIP.";
    private string _inventoryText = "Inventário SafeRead indisponível até o login.";
    private string _readMapText = "Mapa de leituras autenticadas indisponível até clicar em Mapear leituras.";
    private string _voltage = "—";
    private string _biasCurrent = "—";
    private string _loid = "—";
    private string _gponSerial = "—";
    private string _sessionPhase = "Detecção pública";
    private string _observationText = "Observação GET indisponível até autenticar a F6201B e confirmar o modo laboratório.";
    private string _observationCounters = "GET observados: 0";

    public MainViewModel(
        IListEthernetAdaptersUseCase listAdapters,
        IDetectOntUseCase detectOnt,
        ITestConnectionUseCase testConnection,
        IExportPublicDiagnosticUseCase exportDiagnostic,
        IExportAuthenticatedDiagnosticUseCase exportAuthenticated,
        IMapAuthenticatedReadsUseCase mapReads,
        IExportAuthenticatedReadMapUseCase exportReadMap,
        IExportObservationUseCase exportObservation,
        IPromoteReadContractUseCase promoteContract,
        IAuthenticateDeviceUseCase authenticate,
        IEndAuthenticatedSessionUseCase endSession,
        IOntAuthSessionStore authSession,
        IObservationSessionStore observation,
        LoggingPaths loggingPaths)
    {
        _listAdapters = listAdapters;
        _detectOnt = detectOnt;
        _testConnection = testConnection;
        _exportDiagnostic = exportDiagnostic;
        _exportAuthenticated = exportAuthenticated;
        _mapReads = mapReads;
        _exportReadMap = exportReadMap;
        _exportObservation = exportObservation;
        _promoteContract = promoteContract;
        _authenticate = authenticate;
        _endSession = endSession;
        _authSession = authSession;
        _observation = observation;
        _loggingPaths = loggingPaths;

        Adapters = new ObservableCollection<EthernetAdapterInfo>();
        KnownIpOptions = new ObservableCollection<string> { KnownIp100, KnownIp1, CustomIpLabel };
        DetectCommand = new RelayCommand(DetectAsync, () => !IsBusy);
        TestConnectionCommand = new RelayCommand(TestConnectionAsync, () => !IsBusy);
        RefreshAdaptersCommand = new RelayCommand(LoadAdapters, () => !IsBusy);
        ExportCommand = new RelayCommand(ExportAsync, () => !IsBusy);
        LoginCommand = new RelayCommand(LoginAsync, CanLogin);
        EndSessionCommand = new RelayCommand(EndSessionAsync, () => !IsBusy && IsAuthenticated);
        ExportAuthenticatedCommand = new RelayCommand(ExportAuthenticatedAsync, CanExportAuthenticated);
        MapReadsCommand = new RelayCommand(MapReadsAsync, () => !IsBusy && IsAuthenticated);
        ExportReadMapCommand = new RelayCommand(ExportReadMapAsync, CanExportReadMap);
        ObserveNavigationCommand = new RelayCommand(ObserveNavigationAsync, CanObserve);
        ExportObservationCommand = new RelayCommand(ExportObservationAsync, CanExportObservation);
        PromoteContractCommand = new RelayCommand(PromoteContractAsync, CanPromoteContract);
        LoadAdapters();
    }

    public event EventHandler? ClearPasswordRequested;
    public event EventHandler<ObservationLaunchRequest>? ObservationWindowRequested;
    public event EventHandler? ObservationMustStop;

    public ObservableCollection<EthernetAdapterInfo> Adapters { get; }
    public ObservableCollection<string> KnownIpOptions { get; }
    public ICommand DetectCommand { get; }
    public ICommand TestConnectionCommand { get; }
    public ICommand RefreshAdaptersCommand { get; }
    public ICommand ExportCommand { get; }
    public ICommand LoginCommand { get; }
    public ICommand EndSessionCommand { get; }
    public ICommand ExportAuthenticatedCommand { get; }
    public ICommand MapReadsCommand { get; }
    public ICommand ExportReadMapCommand { get; }
    public ICommand ObserveNavigationCommand { get; }
    public ICommand ExportObservationCommand { get; }
    public ICommand PromoteContractCommand { get; }

    public string ProductName => "Tanto ONT Manager";
    public string ModeLabel => OperationMode.LaboratoryReadOnly.ToUiLabel();
    public string VersionLabel => "v" + (Assembly.GetExecutingAssembly()
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? ProductInfo.Version);

    public string LogPath => _loggingPaths.CurrentHint;
    public bool IsAuthenticationMapped => _lastProbe is not null
                                          && string.Equals(_lastProbe.Model, DeviceModelIds.ZteF6201B, StringComparison.Ordinal)
                                          && _lastProbe.Confidence >= 0.55
                                          && _lastReport?.Capabilities?.AuthenticationMapped == true;

    public bool IsAuthenticated => _authSession.DomainSession?.IsAuthenticated == true
                                   && _authState == AuthSessionState.AuthenticatedReadOnly;

    public AuthSessionState AuthState
    {
        get => _authState;
        private set
        {
            if (SetProperty(ref _authState, value))
            {
                RaisePropertyChanged(nameof(AuthStateLabel));
                RaisePropertyChanged(nameof(IsAuthenticated));
                RaiseCanExecute();
            }
        }
    }

    public string AuthStateLabel => AuthState.ToUiLabel();

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
                EndSessionIfBoundToDifferentIp();
                RaisePropertyChanged(nameof(IsCustomIp));
                RaisePropertyChanged(nameof(ExpectedOntIp));
                RaiseCanExecute();
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
                EndSessionIfBoundToDifferentIp();
                RaisePropertyChanged(nameof(ExpectedOntIp));
                RaiseCanExecute();
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
        set
        {
            if (SetProperty(ref _username, value))
            {
                RaiseCanExecute();
            }
        }
    }

    public bool DoNotPersistCredential
    {
        get => _doNotPersistCredential;
        set => SetProperty(ref _doNotPersistCredential, value);
    }

    public bool TrustLocalCertificate
    {
        get => _trustLocalCertificate;
        set
        {
            if (SetProperty(ref _trustLocalCertificate, value))
            {
                RaiseCanExecute();
            }
        }
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
                (ExportCommand as RelayCommand)?.RaiseCanExecuteChanged();
                RaiseCanExecute();
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
    public string HttpStatus { get => _httpStatus; set => SetProperty(ref _httpStatus, value); }
    public string PublicTitle { get => _publicTitle; set => SetProperty(ref _publicTitle, value); }
    public string ResponseSize { get => _responseSize; set => SetProperty(ref _responseSize, value); }
    public string ShortHash { get => _shortHash; set => SetProperty(ref _shortHash, value); }
    public string ConfidenceLabel { get => _confidenceLabel; set => SetProperty(ref _confidenceLabel, value); }
    public string EvidenceText { get => _evidenceText; set => SetProperty(ref _evidenceText, value); }
    public string ProbeDetails { get => _probeDetails; set => SetProperty(ref _probeDetails, value); }
    public string ExportPath { get => _exportPath; set => SetProperty(ref _exportPath, value); }
    public bool DetailsExpanded { get => _detailsExpanded; set => SetProperty(ref _detailsExpanded, value); }
    public string LoginPostCount { get => _loginPostCount; set => SetProperty(ref _loginPostCount, value); }
    public string LogoutPostCount { get => _logoutPostCount; set => SetProperty(ref _logoutPostCount, value); }
    public string ConfigPostCount { get => _configPostCount; set => SetProperty(ref _configPostCount, value); }
    public string ZipInspection { get => _zipInspection; set => SetProperty(ref _zipInspection, value); }
    public string InventoryText { get => _inventoryText; set => SetProperty(ref _inventoryText, value); }
    public string ReadMapText { get => _readMapText; set => SetProperty(ref _readMapText, value); }
    public string Voltage { get => _voltage; set => SetProperty(ref _voltage, value); }
    public string BiasCurrent { get => _biasCurrent; set => SetProperty(ref _biasCurrent, value); }
    public string Loid { get => _loid; set => SetProperty(ref _loid, value); }
    public string GponSerial { get => _gponSerial; set => SetProperty(ref _gponSerial, value); }
    public string SessionPhase { get => _sessionPhase; set => SetProperty(ref _sessionPhase, value); }
    public string ObservationText { get => _observationText; set => SetProperty(ref _observationText, value); }
    public string ObservationCounters { get => _observationCounters; set => SetProperty(ref _observationCounters, value); }

    public SecureString Password { get; private set; } = new();

    public void SetPassword(SecureString password)
    {
        Password.Dispose();
        Password = password.Copy();
        RaiseCanExecute();
    }

    public void ClearSecrets()
    {
        Username = string.Empty;
        Password.Dispose();
        Password = new SecureString();
        ClearPasswordRequested?.Invoke(this, EventArgs.Empty);
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
            EndSessionIfBoundToDifferentIp();
            var report = await _detectOnt.ExecuteAsync(
                new DetectOntCommand(SelectedAdapter, target, TrustLocalCertificate),
                _cts.Token);

            Status = report.Status;
            StatusLabel = report.Status.ToUiLabel();
            LastDuration = FormatDuration(report.Duration);
            ConfidenceLabel = report.Confidence.ToUiLabel();
            EvidenceText = report.EvidenceList.Count == 0
                ? "Nenhuma evidência pública suficiente."
                : string.Join(Environment.NewLine, report.EvidenceList);
            Recommendations = string.Join(Environment.NewLine + Environment.NewLine, report.Recommendations.Select(item => $"{item.Title}{Environment.NewLine}{item.Details}"));
            ApplyObservation(report.PublicObservation);

            if (report.Device is { } device)
            {
                Manufacturer = device.Identity.Manufacturer;
                Model = device.Identity.Model ?? "Não confirmado";
                Hardware = device.Identity.Firmware.HardwareDisplay;
                Firmware = device.Identity.Firmware.SoftwareDisplay;
                Boot = device.Identity.Firmware.BootDisplay;
                Serial = SensitiveDataMasker.MaskSerial(device.Identity.SerialNumber);
                Mac = SensitiveDataMasker.MaskMac(device.Identity.MacAddress);
                _lastProbe = AdapterProbeResult.Match(
                    device.AdapterId,
                    device.Identity.Manufacturer,
                    device.Identity.Model,
                    device.Confidence,
                    device.Endpoint,
                    device.Evidence.Select(item => new ProbeEvidence("public-html", item)).ToList(),
                    report.Capabilities?.LoginFormVisible == true,
                    device.Endpoint.Scheme == "https");
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
                OpticalPower = FormatOptical(diagnostics.Optical, false);
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

            _lastReport = report;
            RaisePropertyChanged(nameof(IsAuthenticationMapped));
            if (IsAuthenticationMapped && report.Status == ApplicationStatus.Detected)
            {
                AuthState = AuthSessionState.ReadyToAuthenticate;
                AuthMessage = "Pronto para autenticar. Informe a credencial da etiqueta e clique em Login uma vez.";
                SessionPhase = "Detecção pública";
                StatusLabel = "Detectado";
            }
            else if (report.Status == ApplicationStatus.ControlledFailure)
            {
                AuthState = AuthSessionState.ControlledFailure;
                ClearSecrets();
            }
            else
            {
                AuthState = AuthSessionState.Unmapped;
            }

            if (report.Status == ApplicationStatus.ControlledFailure)
            {
                ClearSecrets();
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
            ApplyObservation(result.PrimaryObservation);
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

            if (Status == ApplicationStatus.ControlledFailure)
            {
                ClearSecrets();
            }
        });
    }

    private async Task ExportAsync()
    {
        await RunBusyAsync("Exportar diagnóstico público", async () =>
        {
            var password = ReadPasswordForScanOnly();
            try
            {
                var result = await _exportDiagnostic.ExecuteAsync(
                    new ExportPublicDiagnosticCommand(Username, password),
                    _cts.Token);
                if (result.IsFailure)
                {
                    SetFailure(result.Error?.Message + " " + result.Error?.Recommendation);
                    ClearSecrets();
                    return;
                }

                ExportPath = result.Value!;
                LastOperation = "Diagnóstico público sanitizado salvo em " + result.Value;
                Recommendations = "Arquivo gerado somente com a resposta pública. Cookies, senhas e cabeçalhos de autorização não entram no ZIP.";
            }
            finally
            {
                password = null;
            }
        });
    }

    private async Task LoginAsync()
    {
        if (!CanLogin() || _lastProbe is null)
        {
            return;
        }

        if (!TryGetTarget(out var target, out var error))
        {
            SetFailure(error);
            return;
        }

        await RunBusyAsync("Login", async () =>
        {
            AuthState = AuthSessionState.Authenticating;
            _authSession.SetState(AuthSessionState.Authenticating);
            AuthMessage = "Autenticando — um único POST no endpoint de login observado.";
            using var credentials = new DeviceCredentials(Username, Password.Copy(), false);
            var result = await _authenticate.ExecuteAsync(
                new AuthenticateCommand(
                    _lastProbe.Endpoint,
                    _lastProbe,
                    credentials,
                    TrustLocalCertificate,
                    _lastReport?.PublicObservation?.Certificate.Sha256Fingerprint),
                _cts.Token);

            AuthState = result.SessionState;
            AuthMessage = result.Outcome == AuthenticationOutcome.Succeeded
                ? result.Snapshot!.FirmwareCompatibility.ToAuthenticatedUiLabel() + ". A senha foi removida da memória."
                : result.Error?.Message ?? AuthState.ToUiLabel();
            LastOperation = $"Login: {AuthState.ToUiLabel()} POST={result.PostCount} HTTP={result.HttpStatus?.ToString() ?? "—"}";

            ClearPasswordOnly();

            if (result.Outcome == AuthenticationOutcome.Succeeded && result.Snapshot is { } snapshot)
            {
                Status = ApplicationStatus.Authenticated;
                StatusLabel = snapshot.FirmwareCompatibility.ToAuthenticatedUiLabel();
                SessionPhase = snapshot.FirmwareCompatibility == FirmwareCompatibility.Unconfirmed
                    ? "Sessão autenticada — firmware ainda não confirmada"
                    : "Sessão autenticada";
                ApplySnapshot(snapshot);
            }
            else if (result.SessionState == AuthSessionState.CertificateChanged)
            {
                _authSession.End("certificado-alterado");
                Recommendations = "O certificado TLS mudou. Confirme novamente a confiança local e detecte a ONT.";
            }
        });
    }

    private async Task MapReadsAsync()
    {
        await RunBusyAsync("Mapear leituras", async () =>
        {
            var result = await _mapReads.ExecuteAsync(_cts.Token);
            if (result.IsFailure || result.Value is null)
            {
                LastOperation = result.Error?.Message ?? "Falha ao mapear leituras autenticadas.";
                Recommendations = LastOperation;
                AuthMessage = LastOperation;
                AuthState = _authSession.State;
                RaiseCanExecute();
                return;
            }

            var map = result.Value;
            LoginPostCount = map.LoginPostCount.ToString();
            LogoutPostCount = map.LogoutPostCount.ToString();
            ConfigPostCount = map.ConfigPostCount.ToString();
            ReadMapText = map.ToOperatorText();
            SessionPhase = "Mapear leituras autenticadas";
            LastOperation =
                $"Mapa: {map.TotalCandidates} candidatos · SafeRead {map.SafeReadCount} · bloqueados {map.BlockedCount} · duplicados {map.DuplicateCount}. POST login={map.LoginPostCount} POST logout={map.LogoutPostCount} POST configuração={map.ConfigPostCount}";
            Recommendations = map.Note;
            if (_authSession.Snapshot is { } snapshot)
            {
                ApplySnapshot(snapshot);
                if (snapshot.FirmwareCompatibility == FirmwareCompatibility.Unconfirmed)
                {
                    AuthMessage = FirmwareCompatibilityDisplay.AuthenticatedUnconfirmed;
                    SessionPhase = "Sessão autenticada — firmware ainda não confirmada";
                    return;
                }
            }

            AuthMessage = map.PriorityMissing.Count == 0
                ? "Mapa autenticado concluído. Somente GET após o login."
                : "Mapa autenticado concluído. Telas prioritárias sem evidência não foram adivinhadas.";
        });
    }

    private async Task ExportReadMapAsync()
    {
        await RunBusyAsync("Exportar mapa sanitizado", async () =>
        {
            var result = await _exportReadMap.ExecuteAsync(_cts.Token);
            if (result.IsFailure || result.Value is null)
            {
                LastOperation = result.Error?.Message ?? "Falha ao exportar o mapa sanitizado.";
                Recommendations = LastOperation;
                return;
            }

            ExportPath = result.Value.ZipPath;
            ZipInspection = result.Value.Inspection.ToOperatorText();
            LastOperation = "Mapa sanitizado salvo em " + result.Value.ZipPath;
            Recommendations = "Pacote com authenticated-read-map.json e authenticated-read-map.txt, sem HTML, cookies ou tokens.";
        });
    }

    private async Task EndSessionAsync()
    {
        await RunBusyAsync("Encerrar sessão", async () =>
        {
            var result = await _endSession.ExecuteAsync(new EndAuthenticatedSessionCommand(true), _cts.Token);
            var logout = result.Value;
            AuthState = IsAuthenticationMapped ? AuthSessionState.ReadyToAuthenticate : AuthSessionState.Unmapped;
            Status = ApplicationStatus.Detected;
            StatusLabel = "Detectado — sessão encerrada";
            SessionPhase = "Sessão encerrada";
            AuthMessage = logout?.Message ?? "Sessão local encerrada; invalidação remota não confirmada";
            LoginPostCount = (logout?.LoginPostCount ?? 0).ToString();
            LogoutPostCount = (logout?.LogoutPostCount ?? 0).ToString();
            ConfigPostCount = "0";
            LastOperation = AuthMessage + $" POST login={LoginPostCount} POST logout={LogoutPostCount} POST configuração=0";
            ReadMapText = "Mapa de leituras autenticadas indisponível até clicar em Mapear leituras.";
            StopObservation("sessão encerrada");
            RaiseCanExecute();
        });
    }

    private async Task ExportAuthenticatedAsync()
    {
        await RunBusyAsync("Exportar diagnóstico autenticado", async () =>
        {
            var password = ReadPasswordForScanOnly();
            try
            {
                var result = await _exportAuthenticated.ExecuteAsync(
                    new ExportAuthenticatedDiagnosticCommand(Username, password),
                    _cts.Token);
                if (result.IsFailure)
                {
                    SetFailure(result.Error?.Message + " " + result.Error?.Recommendation);
                    return;
                }

                ExportPath = result.Value!.ZipPath;
                ZipInspection = result.Value.Inspection.ToOperatorText();
                LastOperation = "Diagnóstico autenticado sanitizado salvo em " + result.Value.ZipPath;
                Status = ApplicationStatus.DiagnosticsCompleted;
                StatusLabel = "Autenticado — somente leitura";
                Recommendations = "Pacote autenticado sem HTML bruto, cookies ou credenciais."
                                  + Environment.NewLine + ZipInspection;
            }
            finally
            {
                password = null;
            }
        });
    }

    private void ApplySnapshot(AuthenticatedReadSnapshot snapshot)
    {
        Manufacturer = snapshot.Identity.Manufacturer;
        Model = snapshot.Identity.Model ?? Model;
        Hardware = FirmwareInfo.Display(snapshot.Identity.Firmware.HardwareVersion, true);
        Firmware = FirmwareInfo.Display(snapshot.Identity.Firmware.SoftwareVersion, true);
        Boot = FirmwareInfo.Display(snapshot.Identity.Firmware.BootVersion, true);
        Serial = snapshot.Identity.SerialNumber is null
            ? FirmwareInfo.AuthenticatedMissing
            : SensitiveDataMasker.MaskSerial(snapshot.Identity.SerialNumber);
        Mac = snapshot.Identity.MacAddress is null
            ? FirmwareInfo.AuthenticatedMissing
            : SensitiveDataMasker.MaskMac(snapshot.Identity.MacAddress);
        Pon = PonState.FormatOnuState(snapshot.Diagnostics.Pon.OnuState, true);
        Temperature = FirmwareInfo.Display(snapshot.Diagnostics.Optical.Temperature, true);
        Voltage = FirmwareInfo.Display(snapshot.Diagnostics.Optical.Voltage, true);
        BiasCurrent = FirmwareInfo.Display(snapshot.Diagnostics.Optical.BiasCurrent, true);
        Loid = FirmwareInfo.Display(snapshot.Diagnostics.Pon.Loid, true);
        GponSerial = snapshot.Diagnostics.Pon.GponSerial is null
            ? FirmwareInfo.AuthenticatedMissing
            : SensitiveDataMasker.MaskSerial(snapshot.Diagnostics.Pon.GponSerial);
        OpticalPower = FormatOptical(snapshot.Diagnostics.Optical, true);
        WanProfiles = snapshot.Diagnostics.WanProfiles.Count == 0
            ? FirmwareInfo.AuthenticatedMissing
            : string.Join(Environment.NewLine + Environment.NewLine, snapshot.Diagnostics.WanProfiles.Select(FormatWan));
        LoginPostCount = snapshot.LoginPostCount.ToString();
        LogoutPostCount = snapshot.LogoutPostCount.ToString();
        ConfigPostCount = snapshot.ConfigPostCount.ToString();
        InventoryText = snapshot.Inventory.Count == 0
            ? "Nenhuma tag inventariada."
            : string.Join(Environment.NewLine, snapshot.Inventory.Select(item =>
                $"{item.Tag} · {item.Classification} · {(item.WasAccessed ? "acessada" : "não acessada")} · {item.ClassificationReason}"));
        Recommendations = snapshot.FirmwareCompatibility.ToAuthenticatedUiLabel() + ". "
                          + $"POST login: {snapshot.LoginPostCount}. "
                          + "POST configuração: 0. "
                          + "Páginas GET: "
                          + string.Join(", ", snapshot.PagesRead)
                          + ".";
        if (snapshot.FirmwareCompatibility == FirmwareCompatibility.Unconfirmed)
        {
            StatusLabel = FirmwareCompatibilityDisplay.AuthenticatedUnconfirmed;
        }
        else if (snapshot.FirmwareCompatibility == FirmwareCompatibility.ConfirmedCompatible)
        {
            StatusLabel = FirmwareCompatibilityDisplay.AuthenticatedCompatible;
        }
    }

    private static string FormatWan(WanProfile profile)
        => string.Join(Environment.NewLine, new[]
        {
            "Connection Name: " + profile.Name,
            profile.Mode is null ? null : "Type: " + profile.Mode,
            profile.ServiceList is null ? null : "Service List: " + profile.ServiceList,
            profile.LinkType is null ? null : "Link Type: " + profile.LinkType,
            profile.AddressFamily is null ? null : "IP Version: " + profile.AddressFamily,
            profile.IpType is null ? null : "IPv4 Type: " + profile.IpType,
            profile.NatEnabled is null ? null : "NAT: " + (profile.NatEnabled.Value ? "enabled" : "disabled"),
            profile.VlanEnabled is null ? null : "VLAN enabled: " + (profile.VlanEnabled.Value ? "yes" : "no"),
            profile.VlanId is null ? null : "VLAN ID: " + profile.VlanId,
            profile.Priority8021p is null ? null : "802.1p: " + profile.Priority8021p,
            profile.ConnectionState is null ? null : "IPv4 status: " + profile.ConnectionState,
            profile.DisconnectReason is null ? null : "Disconnect: " + profile.DisconnectReason,
            profile.Ipv4Address is null ? null : "IP: " + profile.Ipv4Address,
            profile.MacAddress is null ? null : "MAC: " + profile.MacAddress,
            profile.PppoeUsername is null ? null : "PPPoE user: " + profile.PppoeUsername
        }.Where(part => !string.IsNullOrWhiteSpace(part)));

    private static string FormatOptical(OpticalReading optical, bool authenticated)
    {
        var tx = ScalarOrNull(optical.TxPower);
        var rx = ScalarOrNull(optical.RxPower);
        if (tx is null && rx is null)
        {
            return authenticated ? FirmwareInfo.AuthenticatedMissing : FirmwareInfo.PublicMissing;
        }

        return $"Tx {tx ?? "—"} / Rx {rx ?? "—"}";
    }

    private static string? ScalarOrNull(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Contains('<') || value.Length > 96)
        {
            return null;
        }

        var trimmed = value.Trim();
        if (!trimmed.Any(char.IsDigit)
            && (trimmed.Contains("Transmit", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("Receive", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        return trimmed;
    }

    private bool CanLogin()
        => !IsBusy
           && IsAuthenticationMapped
           && TrustLocalCertificate
           && _lastProbe is not null
           && TryGetTarget(out var target, out _)
           && target.Equals(_lastProbe.Endpoint.Address)
           && !string.IsNullOrWhiteSpace(Username)
           && Password.Length > 0
           && AuthState is AuthSessionState.ReadyToAuthenticate
               or AuthSessionState.CredentialRejected
               or AuthSessionState.ControlledFailure
               or AuthSessionState.Unmapped
           && AuthState != AuthSessionState.Authenticating
           && !IsAuthenticated;

    private bool CanExportAuthenticated()
        => !IsBusy && IsAuthenticated && _authSession.Snapshot is not null;

    private bool CanExportReadMap()
        => !IsBusy && IsAuthenticated && _authSession.ReadMap is not null;

    private bool CanObserve()
        => !IsBusy
           && IsAuthenticated
           && IsAuthenticationMapped
           && _authSession.Transport is not null
           && TryGetTarget(out var target, out _)
           && _authSession.IsBoundTo(target, _authSession.DomainSession?.BoundCertificateSha256);

    private bool CanExportObservation()
        => !IsBusy && (_observation.Engine is not null || _observation.LastSnapshot is not null);

    private bool CanPromoteContract()
        => CanExportObservation();

    private Task ObserveNavigationAsync()
    {
        if (!CanObserve() || _authSession.Transport is null || _authSession.DomainSession is null)
        {
            return Task.CompletedTask;
        }

        var folder = Path.Combine(_loggingPaths.RootDirectory, "observer-webview", Guid.NewGuid().ToString("N"));
        var engine = new ObservationEngine(_authSession.Transport.BoundAddress);
        _observation.Attach(engine, folder);
        var request = new ObservationLaunchRequest(
            _authSession.Transport.BoundAddress,
            _authSession.DomainSession.Endpoint.BaseUri,
            _authSession.Transport.CopyCookiesForIsolatedObserver(),
            folder);
        ObservationWindowRequested?.Invoke(this, request);
        ObservationText = "Observador GET aberto. Navegue manualmente nas telas Device/PON/WAN. POST permanece bloqueado.";
        LastOperation = "Observar navegação GET iniciado em WebView2 isolado.";
        RaiseCanExecute();
        return Task.CompletedTask;
    }

    private async Task ExportObservationAsync()
    {
        await RunBusyAsync("Exportar observação sanitizada", async () =>
        {
            RefreshObservationPanel();
            var result = await _exportObservation.ExecuteAsync(_cts.Token);
            if (result.IsFailure || result.Value is null)
            {
                LastOperation = result.Error?.Message ?? "Falha ao exportar a observação.";
                return;
            }

            ExportPath = result.Value.ZipPath;
            ZipInspection = result.Value.Inspection.ToOperatorText();
            LastOperation = "Observação sanitizada salva em " + result.Value.ZipPath;
        });
    }

    private async Task PromoteContractAsync()
    {
        await RunBusyAsync("Promover contrato de leitura", async () =>
        {
            var result = await _promoteContract.ExecuteAsync(_cts.Token);
            if (result.IsFailure || result.Value is null)
            {
                LastOperation = result.Error?.Message ?? "Falha ao gravar a proposta.";
                return;
            }

            ExportPath = result.Value;
            LastOperation = "Proposta local gravada sem alterar o adaptador: " + result.Value;
            Recommendations = "A proposta não entra na allowlist. Firmware Unconfirmed continua sem escrita.";
        });
    }

    private void StopObservation(string reason)
    {
        if (_observation.IsOpen || _observation.Engine is not null)
        {
            _observation.Engine?.EndBecauseIpChanged();
            ObservationMustStop?.Invoke(this, EventArgs.Empty);
            _observation.FinishAndDestroy();
        }

        ObservationText = "Observação encerrada (" + reason + "). Cookies temporários do WebView2 foram destruídos.";
        RefreshObservationPanel();
    }

    public IObservationSessionStore ObservationSession => _observation;

    public void DeclineObservation() => StopObservation("não confirmado");

    public void RefreshObservationPanel()
    {
        var snapshot = _observation.Engine?.Snapshot() ?? _observation.LastSnapshot;
        if (snapshot is null)
        {
            ObservationCounters = "GET observados: 0";
            return;
        }

        var counters = snapshot.Counters;
        ObservationCounters =
            $"GET observados: {counters.GetsObserved}{Environment.NewLine}" +
            $"GET permitidos: {counters.GetsAllowed}{Environment.NewLine}" +
            $"Requisições bloqueadas: {counters.RequestsBlocked}{Environment.NewLine}" +
            $"POST observados e bloqueados: {counters.PostsObservedAndBlocked}{Environment.NewLine}" +
            "POST de configuração enviados: 0";
        ObservationText = snapshot.SummaryText;
    }

    private void EndSessionIfBoundToDifferentIp()
    {
        if (_authSession.DomainSession is null)
        {
            return;
        }

        if (!TryGetTarget(out var target, out _) || !_authSession.IsBoundTo(target, _authSession.DomainSession.BoundCertificateSha256))
        {
            StopObservation("ip-ou-alvo-alterado");
            _authSession.End("ip-ou-alvo-alterado");
            AuthState = AuthSessionState.Unmapped;
            AuthMessage = "A sessão anterior foi encerrada porque o IP mudou.";
            SessionPhase = "Detecção pública";
        }
    }

    private void ClearPasswordOnly()
    {
        Password.Dispose();
        Password = new SecureString();
        ClearPasswordRequested?.Invoke(this, EventArgs.Empty);
        RaiseCanExecute();
    }

    private void RaiseCanExecute()
    {
        (LoginCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (EndSessionCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ExportAuthenticatedCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (MapReadsCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ExportReadMapCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ObserveNavigationCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ExportObservationCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (PromoteContractCommand as RelayCommand)?.RaiseCanExecuteChanged();
        RaisePropertyChanged(nameof(IsAuthenticationMapped));
        RaisePropertyChanged(nameof(IsAuthenticated));
    }

    private void ApplyObservation(HttpPublicObservation? observation)
    {
        if (observation is null)
        {
            HttpStatus = "—";
            PublicTitle = "—";
            ResponseSize = "—";
            ShortHash = "—";
            ProbeDetails = "Sem observação HTTP pública.";
            return;
        }

        HttpStatus = observation.StatusDisplay;
        PublicTitle = observation.Title ?? "—";
        ResponseSize = $"{observation.BodyLengthBytes} bytes";
        ShortHash = observation.ShortHash;
        ProbeDetails =
            $"IP: {observation.TargetAddress}{Environment.NewLine}" +
            $"Protocolo: {observation.Scheme}  Porta: {observation.Port}{Environment.NewLine}" +
            $"Método: {string.Join(", ", observation.HttpMethodsUsed.Distinct())}{Environment.NewLine}" +
            $"URI final: {observation.FinalUri}{Environment.NewLine}" +
            $"Redirects: {observation.RedirectCount}{Environment.NewLine}" +
            $"Content-Type: {observation.ContentType ?? "—"}{Environment.NewLine}" +
            $"Charset: {observation.Charset ?? "—"}{Environment.NewLine}" +
            $"Encoding: {observation.DetectedEncoding ?? "—"}{Environment.NewLine}" +
            $"Comprimido: {(observation.ContentWasCompressed ? "sim" : "não")}{Environment.NewLine}" +
            $"Timeout: {(observation.TimedOut ? "sim" : "não")}{Environment.NewLine}" +
            $"Conexão: {observation.ConnectDuration.TotalMilliseconds:0} ms{Environment.NewLine}" +
            $"Total: {observation.TotalDuration.TotalMilliseconds:0} ms{Environment.NewLine}" +
            $"TLS: {observation.Certificate.ErrorCategory}{Environment.NewLine}" +
            $"Certificado: {observation.Certificate.Subject ?? "—"}{Environment.NewLine}" +
            $"Emissor: {observation.Certificate.Issuer ?? "—"}{Environment.NewLine}" +
            $"Validade: {observation.Certificate.NotBefore:u} → {observation.Certificate.NotAfter:u}{Environment.NewLine}" +
            $"SHA-256 cert: {observation.Certificate.Sha256Fingerprint ?? "—"}{Environment.NewLine}" +
            $"Exceção local: {(observation.Certificate.AcceptedByLocalException ? "sim" : "não")}";
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
            ClearSecrets();
        }
        catch (InvalidOperationException ex)
        {
            SetFailure(ex.Message);
            ClearSecrets();
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
        ClearSecrets();
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

    private string? ReadPasswordForScanOnly()
    {
        if (Password.Length == 0)
        {
            return null;
        }

        var pointer = Marshal.SecureStringToGlobalAllocUnicode(Password);
        try
        {
            return Marshal.PtrToStringUni(pointer);
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(pointer);
        }
    }

    private static string FormatDuration(TimeSpan duration)
        => duration.TotalSeconds < 1
            ? $"{duration.TotalMilliseconds:0} ms"
            : $"{duration.TotalSeconds:0.0} s";
}
