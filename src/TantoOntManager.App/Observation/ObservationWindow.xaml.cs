using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.App.Observation;

public partial class ObservationWindow : Window
{
    private readonly ObservationEngine _engine;
    private readonly IObservationSessionStore _store;
    private readonly ObservationLaunchRequest _request;
    private readonly IExportWriteContractUseCase _exportWrite;
    private readonly IPromoteWriteContractUseCase _promoteWrite;
    private readonly DispatcherTimer _refresh = new() { Interval = TimeSpan.FromMilliseconds(400) };
    private readonly HashSet<string> _allowedRequests = new(StringComparer.OrdinalIgnoreCase);
    private readonly ObserverStartupState _startup = new();
    private bool _closing;
    private bool _failed;

    public ObservationWindow(
        ObservationEngine engine,
        IObservationSessionStore store,
        ObservationLaunchRequest request,
        IExportWriteContractUseCase exportWrite,
        IPromoteWriteContractUseCase promoteWrite)
    {
        InitializeComponent();
        _engine = engine;
        _store = store;
        _request = request;
        _exportWrite = exportWrite;
        _promoteWrite = promoteWrite;
        Closed += (_, _) => Cleanup();
        _refresh.Tick += (_, _) => RefreshPanel();
        Loaded += OnLoaded;
    }

    public event EventHandler<ObserverInitializationResult>? InitializationFailed;

    public event EventHandler<string>? WriteCaptureIncompatible;

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            await StartAsync();
        }
        catch (Exception ex)
        {
            FailClosed(ex);
        }
    }

    private async Task StartAsync()
    {
        if (!_startup.TryBegin())
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(_request.UserDataFolder);
            var create = ObserverWebView2CreateRequest.ForIsolatedProfile(_request.UserDataFolder);
            var environment = await CoreWebView2Environment.CreateAsync(
                browserExecutableFolder: create.BrowserExecutableFolder,
                userDataFolder: create.UserDataFolder);
            await WebView.EnsureCoreWebView2Async(environment);
            var core = WebView.CoreWebView2
                       ?? throw new InvalidOperationException("CoreWebView2 não inicializado.");
            _startup.MarkCoreReady();
            core.Settings.AreDefaultContextMenusEnabled = true;
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.AreHostObjectsAllowed = false;
            core.Settings.IsWebMessageEnabled = false;
            core.Settings.IsGeneralAutofillEnabled = false;
            core.Settings.IsPasswordAutosaveEnabled = false;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;
            core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
            core.WebResourceRequested += OnWebResourceRequested;
            core.WebResourceResponseReceived += OnWebResourceResponseReceived;
            core.NewWindowRequested += (_, args) =>
            {
                args.Handled = true;
                _engine.Evaluate(new IncomingObservationRequest("GET", new Uri(args.Uri), IsNewWindow: true));
            };
            core.DownloadStarting += (_, args) =>
            {
                args.Cancel = true;
                args.Handled = true;
                if (Uri.TryCreate(args.DownloadOperation.Uri, UriKind.Absolute, out var uri))
                {
                    _engine.Evaluate(new IncomingObservationRequest("GET", uri, IsDownload: true));
                }
            };
            core.NavigationStarting += (_, args) =>
            {
                if (!Uri.TryCreate(args.Uri, UriKind.Absolute, out var uri))
                {
                    args.Cancel = true;
                    return;
                }

                if (!ObservationHosts.IsBoundHost(uri, _request.BoundAddress))
                {
                    args.Cancel = true;
                    _engine.EndBecauseIpChanged();
                    RequestCloseObserverOnly();
                }
            };
            core.ServerCertificateErrorDetected += (_, args) =>
            {
                args.Action = ObservationHosts.IsBoundHost(new Uri(args.RequestUri), _request.BoundAddress)
                    ? CoreWebView2ServerCertificateErrorAction.AlwaysAllow
                    : CoreWebView2ServerCertificateErrorAction.Cancel;
            };

            if (_startup.TryTransferCookies())
            {
                var cookieManager = core.CookieManager;
                foreach (var seed in _request.Cookies)
                {
                    var cookie = cookieManager.CreateCookie(seed.Name, seed.RevealValueForIsolatedWebView(), seed.Domain, seed.Path);
                    cookie.IsSecure = seed.Secure;
                    cookie.IsHttpOnly = seed.HttpOnly;
                    cookieManager.AddOrUpdateCookie(cookie);
                }
            }

            _refresh.Start();
            StatusText.Text = _request.Cookies.Count == 0
                ? "WebView2 isolado sem cookie transferível. POST permanece bloqueado. Navegue só se a sessão já autenticada carregar."
                : "Sessão isolada com cookies em memória. Navegue manualmente até Internet → WAN. POST de configuração permanece bloqueado.";
            core.Navigate(_request.StartUri.ToString());
            RefreshPanel();
        }
        catch (WebView2RuntimeNotFoundException ex)
        {
            FailClosed(ex);
        }
        catch (FileNotFoundException ex)
        {
            FailClosed(ex);
        }
        catch (Exception ex)
        {
            FailClosed(ex);
        }
    }

    private void FailClosed(Exception exception)
    {
        if (_failed)
        {
            return;
        }

        _failed = true;
        var result = ObserverInitializationGuard.FromException(exception, _startup.CookiesTransferred);
        try
        {
            StatusText.Text = result.OperatorMessage;
        }
        catch (Exception)
        {
            // janela já em fechamento
        }

        InitializationFailed?.Invoke(this, result);
        Cleanup();
        RequestCloseObserverOnly();
    }

    private void RequestCloseObserverOnly()
    {
        if (_closing)
        {
            return;
        }

        _closing = true;
        Dispatcher.BeginInvoke(new Action(() =>
        {
            try
            {
                if (IsVisible || IsLoaded)
                {
                    Close();
                }
            }
            catch (Exception)
            {
                // já fechada
            }
        }), DispatcherPriority.Background);
    }

    private void OnWebResourceRequested(object? sender, CoreWebView2WebResourceRequestedEventArgs args)
    {
        try
        {
            if (!Uri.TryCreate(args.Request.Uri, UriKind.Absolute, out var uri))
            {
                args.Response = CreateBlockedResponse();
                return;
            }

            var method = args.Request.Method;
            if (WriteCandidateClassifier.IsMutatingMethod(method))
            {
                var deferral = args.GetDeferral();
                _ = InspectMutatingAndBlockAsync(args, uri, method, deferral);
                return;
            }

            var decision = _engine.Evaluate(new IncomingObservationRequest(method, uri));
            if (decision.Allowed)
            {
                _allowedRequests.Add(ObservationUrl.Normalize(uri) + "|" + method);
                return;
            }

            args.Response = CreateBlockedResponse();
            if (decision.EndsObservation && _engine.EndedByIpChange)
            {
                RequestCloseObserverOnly();
            }

            Dispatcher.Invoke(RefreshPanel);
        }
        catch (Exception)
        {
            args.Response = CreateBlockedResponse();
        }
    }

    private async Task InspectMutatingAndBlockAsync(
        CoreWebView2WebResourceRequestedEventArgs args,
        Uri uri,
        string method,
        CoreWebView2Deferral deferral)
    {
        string? body = null;
        try
        {
            body = await ReadRequestBodyAsync(args.Request.Content);
            var contentType = ReadRawHeader(args.Request.Headers, "Content-Type");
            var referer = ReadRawHeader(args.Request.Headers, "Referer");
            var payload = WriteBodyInspector.ToPayload(contentType, body, referer, null, null);
            body = null;
            var decision = _engine.Evaluate(new IncomingObservationRequest(method, uri), payload);
            args.Response = CreateBlockedResponse();
            if (decision.EndsObservation && _engine.EndedByIpChange)
            {
                await Dispatcher.InvokeAsync(RequestCloseObserverOnly);
            }
            else
            {
                await Dispatcher.InvokeAsync(RefreshPanel);
            }
        }
        catch (Exception)
        {
            try
            {
                args.Response = CreateBlockedResponse();
            }
            catch (Exception)
            {
                // CoreWebView2 já encerrado
            }
        }
        finally
        {
            body = null;
            deferral.Complete();
        }
    }

    private static async Task<string?> ReadRequestBodyAsync(Stream? stream)
    {
        if (stream is null)
        {
            return null;
        }

        try
        {
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 4096, leaveOpen: true);
            var buffer = new char[65536];
            var read = await reader.ReadAsync(buffer, 0, buffer.Length);
            return read <= 0 ? string.Empty : new string(buffer, 0, read);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private async void OnWebResourceResponseReceived(object? sender, CoreWebView2WebResourceResponseReceivedEventArgs args)
    {
        try
        {
            if (!Uri.TryCreate(args.Request.Uri, UriKind.Absolute, out var uri))
            {
                return;
            }

            var method = args.Request.Method;
            if (!_allowedRequests.Contains(ObservationUrl.Normalize(uri) + "|" + method))
            {
                return;
            }

            string? body = string.Empty;
            try
            {
                using var stream = await args.Response.GetContentAsync();
                if (stream is not null)
                {
                    using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 4096, leaveOpen: false);
                    var buffer = new char[262144];
                    var read = await reader.ReadAsync(buffer, 0, buffer.Length);
                    body = new string(buffer, 0, read);
                }
            }
            catch (Exception)
            {
                body = string.Empty;
            }

            _engine.CompleteGet(
                new IncomingObservationRequest(
                    method,
                    uri,
                    Initiator: TryHeader(args.Request.Headers, "Referer"),
                    RequestContext: ReadRequestContext(args.Request.Headers, uri)),
                args.Response.StatusCode,
                TryHeader(args.Response.Headers, "Content-Type"),
                body,
                TryHeader(args.Request.Headers, "Referer"));
            await Dispatcher.InvokeAsync(RefreshPanel);
        }
        catch (Exception)
        {
            // A captura não deve derrubar o observador; o GET já foi classificado no gate.
        }
    }

    private CoreWebView2WebResourceResponse CreateBlockedResponse()
    {
        var empty = new MemoryStream(Encoding.UTF8.GetBytes("blocked"));
        return WebView.CoreWebView2.Environment.CreateWebResourceResponse(empty, 403, "Blocked", "Content-Type: text/plain");
    }

    private static ObservedRequestContext ReadRequestContext(CoreWebView2HttpRequestHeaders headers, Uri uri)
    {
        var cookieNames = ReadCookieNames(headers);
        var query = ObservationUrl.ParseQuery(uri.Query);
        var tokenPresent = query.Keys.Any(key => key.Equals("_sessionTOKEN", StringComparison.OrdinalIgnoreCase));
        var tokenLength = 0;
        if (tokenPresent && query.TryGetValue("_sessionTOKEN", out var token))
        {
            tokenLength = token.Length;
        }

        var xhr = HeaderPresent(headers, "X-Requested-With");
        return new ObservedRequestContext(
            HeaderPresent(headers, "Referer"),
            HeaderPresent(headers, "Origin"),
            xhr,
            HeaderPresent(headers, "Accept"),
            HeaderPresent(headers, "Accept-Language"),
            cookieNames,
            tokenPresent,
            tokenLength,
            xhr ? "xhr" : "other");
    }

    private static IReadOnlyList<string> ReadCookieNames(CoreWebView2HttpRequestHeaders headers)
    {
        if (!HeaderPresent(headers, "Cookie"))
        {
            return [];
        }

        try
        {
            var header = headers.GetHeader("Cookie");
            return header.Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Select(part => part.Split('=', 2)[0].Trim())
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception)
        {
            return [];
        }
    }

    private static bool HeaderPresent(CoreWebView2HttpRequestHeaders headers, string name)
    {
        try
        {
            return headers.Contains(name);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static string? ReadRawHeader(CoreWebView2HttpRequestHeaders headers, string name)
    {
        try
        {
            return headers.Contains(name) ? headers.GetHeader(name) : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string? TryHeader(CoreWebView2HttpRequestHeaders headers, string name)
        => ReadHeader(headers.Contains(name), () => headers.GetHeader(name));

    private static string? TryHeader(CoreWebView2HttpResponseHeaders headers, string name)
        => ReadHeader(headers.Contains(name), () => headers.GetHeader(name));

    private static string? ReadHeader(bool present, Func<string> getter)
    {
        if (!present)
        {
            return null;
        }

        try
        {
            var value = ObservationSanitizer.SanitizeText(getter());
            return value.Length > 120 ? value[..120] : value;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private void OnDevice(object sender, RoutedEventArgs e) => Capture(ObservationScreen.Device);

    private void OnPon(object sender, RoutedEventArgs e) => Capture(ObservationScreen.Pon);

    private void OnWanStatus(object sender, RoutedEventArgs e) => Capture(ObservationScreen.WanStatus);

    private void OnWanConfig(object sender, RoutedEventArgs e) => Capture(ObservationScreen.WanConfig);

    private void OnCloseBaseline(object sender, RoutedEventArgs e)
    {
        _engine.CloseBaseline();
        StatusText.Text = "Baseline do shell fechada. Clique numa tela e navegue manualmente durante 20 s.";
        RefreshPanel();
    }

    private void Capture(ObservationScreen screen)
    {
        _engine.StartScreenCapture(screen);
        StatusText.Text = $"Capturando {screen.ToOperatorLabel()} por {ObservationScreens.CaptureSeconds} s. Abra a tela correspondente na ONT.";
        RefreshPanel();
    }

    private void OnStartWriteCapture(object sender, RoutedEventArgs e)
    {
        var result = _engine.StartBlockedWriteCapture(_request.WriteEligibility(ConfirmationBox.Text));
        if (result.IsFailure)
        {
            StatusText.Text = result.Error?.Message ?? "A captura bloqueada foi recusada.";
            if (result.Error?.Code == ErrorCodes.WriteCaptureFirmwareIncompatible)
            {
                WriteCaptureIncompatible?.Invoke(this, StatusText.Text);
            }

            RefreshPanel();
            return;
        }

        StatusText.Text = "Captura bloqueada iniciada. Preencha a tela oficial e clique em Apply/Save. Nada será enviado à ONT.";
        RefreshPanel();
    }

    private void OnCancelWriteCapture(object sender, RoutedEventArgs e)
    {
        _engine.CancelWriteCapture();
        StatusText.Text = "Captura de gravação cancelada. POST continua bloqueado.";
        RefreshPanel();
    }

    private async void OnExportWriteContract(object sender, RoutedEventArgs e)
    {
        var result = await _exportWrite.ExecuteAsync(CancellationToken.None);
        StatusText.Text = result.IsFailure
            ? result.Error?.Message ?? "Falha ao exportar a proposta sanitizada."
            : "Proposta sanitizada exportada para " + result.Value!.DirectoryPath;
        RefreshPanel();
    }

    private async void OnPromoteWriteContract(object sender, RoutedEventArgs e)
    {
        var result = await _promoteWrite.ExecuteAsync(CancellationToken.None);
        StatusText.Text = result.IsFailure
            ? result.Error?.Message ?? "Falha ao gravar a proposta local."
            : "Proposta CandidateOnly gravada sem alterar o adaptador: " + result.Value;
        RefreshPanel();
    }

    private void OnCloseObserver(object sender, RoutedEventArgs e) => Close();

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        _engine.Cancel();
        try
        {
            WebView.CoreWebView2?.Stop();
        }
        catch (Exception)
        {
            // já encerrado
        }

        StatusText.Text = "Observação cancelada. Requisições pendentes foram interrompidas.";
        RefreshPanel();
    }

    private void RefreshPanel()
    {
        var counters = _engine.Counters;
        CountersText.Text = WriteContractProposalBuilder.OperatorCounters(counters, _engine.WriteCandidate)
                            + Environment.NewLine
                            + $"GET observados: {counters.GetsObserved}{Environment.NewLine}"
                            + $"GET permitidos: {counters.GetsAllowed}{Environment.NewLine}"
                            + $"Requisições bloqueadas: {counters.RequestsBlocked}{Environment.NewLine}"
                            + $"POST observados e bloqueados: {counters.PostsObservedAndBlocked}";
        TableText.Text = _engine.ToOperatorTable();
        StartWriteCaptureButton.IsEnabled = !_engine.WriteCaptureSpent && _engine.WriteCandidate is null;
        if (_engine.EndedByIpChange)
        {
            StatusText.Text = "Observação encerrada: destino diferente do IP da ONT.";
        }
        else if (_engine.WriteCandidate is not null
                 && !StatusText.Text.Contains("Proposta", StringComparison.Ordinal)
                 && !StatusText.Text.Contains("exportada", StringComparison.OrdinalIgnoreCase))
        {
            StatusText.Text = "Contrato candidato capturado e bloqueado. Feche o observador e abra uma nova sessão para outra tentativa.";
        }
    }

    private void Cleanup()
    {
        if (!_startup.TryCleanup())
        {
            return;
        }

        _refresh.Stop();
        try
        {
            if (_startup.CoreReady)
            {
                WebView.CoreWebView2?.CookieManager.DeleteAllCookies();
                WebView.CoreWebView2?.Stop();
            }
        }
        catch (Exception)
        {
            // encerramento best-effort com inicialização parcial
        }

        _store.FinishAndDestroy();
        ObserverInitializationGuard.DestroyTemporaryFolder(_request.UserDataFolder);
        if (_startup.TryDisposeWebView())
        {
            try
            {
                WebView.Dispose();
            }
            catch (Exception)
            {
                // Dispose duplicado ou controle já destruído
            }
        }
    }
}
