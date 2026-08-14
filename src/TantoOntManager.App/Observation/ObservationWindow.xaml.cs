using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using TantoOntManager.Application.Contracts;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.App.Observation;

public partial class ObservationWindow : Window
{
    private readonly ObservationEngine _engine;
    private readonly IObservationSessionStore _store;
    private readonly ObservationLaunchRequest _request;
    private readonly DispatcherTimer _refresh = new() { Interval = TimeSpan.FromMilliseconds(400) };
    private readonly HashSet<string> _allowedRequests = new(StringComparer.OrdinalIgnoreCase);
    private bool _initialized;

    public ObservationWindow(ObservationEngine engine, IObservationSessionStore store, ObservationLaunchRequest request)
    {
        InitializeComponent();
        _engine = engine;
        _store = store;
        _request = request;
        Closed += (_, _) => Cleanup();
        _refresh.Tick += (_, _) => RefreshPanel();
        Loaded += async (_, _) => await StartAsync();
    }

    private async Task StartAsync()
    {
        Directory.CreateDirectory(_request.UserDataFolder);
        var environment = await CoreWebView2Environment.CreateAsync(_request.UserDataFolder);
        await WebView.EnsureCoreWebView2Async(environment);
        var core = WebView.CoreWebView2;
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
                return;
            }

            if (ObservationRequestGate.HasActionToken(uri))
            {
                args.Cancel = true;
            }
        };
        core.ServerCertificateErrorDetected += (_, args) =>
        {
            args.Action = ObservationHosts.IsBoundHost(new Uri(args.RequestUri), _request.BoundAddress)
                ? CoreWebView2ServerCertificateErrorAction.AlwaysAllow
                : CoreWebView2ServerCertificateErrorAction.Cancel;
        };

        var cookieManager = core.CookieManager;
        foreach (var seed in _request.Cookies)
        {
            var cookie = cookieManager.CreateCookie(seed.Name, seed.RevealValueForIsolatedWebView(), seed.Domain, seed.Path);
            cookie.IsSecure = seed.Secure;
            cookie.IsHttpOnly = seed.HttpOnly;
            cookieManager.AddOrUpdateCookie(cookie);
        }

        _initialized = true;
        _refresh.Start();
        StatusText.Text = _request.Cookies.Count == 0
            ? "WebView2 isolado sem cookie transferível. POST permanece bloqueado. Navegue só se a sessão já autenticada carregar."
            : "Sessão isolada com cookies em memória. Navegue manualmente: Status, PON Information, WAN Status e WAN.";
        core.Navigate(_request.StartUri.ToString());
        RefreshPanel();
    }

    private void OnWebResourceRequested(object? sender, CoreWebView2WebResourceRequestedEventArgs args)
    {
        if (!Uri.TryCreate(args.Request.Uri, UriKind.Absolute, out var uri))
        {
            args.Response = CreateBlockedResponse();
            return;
        }

        var decision = _engine.Evaluate(new IncomingObservationRequest(args.Request.Method, uri));
        if (decision.Allowed)
        {
            _allowedRequests.Add(ObservationUrl.Normalize(uri) + "|" + args.Request.Method);
            return;
        }

        args.Response = CreateBlockedResponse();
        Dispatcher.Invoke(RefreshPanel);
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
                new IncomingObservationRequest(method, uri, Initiator: TryHeader(args.Request.Headers, "Referer")),
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
        CountersText.Text =
            $"GET observados: {counters.GetsObserved}{Environment.NewLine}" +
            $"GET permitidos: {counters.GetsAllowed}{Environment.NewLine}" +
            $"Requisições bloqueadas: {counters.RequestsBlocked}{Environment.NewLine}" +
            $"POST observados e bloqueados: {counters.PostsObservedAndBlocked}{Environment.NewLine}" +
            "POST de configuração enviados: 0";
        TableText.Text = _engine.ToOperatorTable();
        if (_engine.EndedByIpChange)
        {
            StatusText.Text = "Observação encerrada: destino diferente do IP da ONT.";
        }
    }

    private void Cleanup()
    {
        _refresh.Stop();
        try
        {
            WebView.CoreWebView2?.CookieManager.DeleteAllCookies();
            WebView.CoreWebView2?.Stop();
        }
        catch (Exception)
        {
            // encerramento best-effort
        }

        _store.FinishAndDestroy();
        if (_initialized)
        {
            WebView.Dispose();
        }
    }
}
