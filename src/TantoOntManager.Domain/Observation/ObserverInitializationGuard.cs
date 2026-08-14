using TantoOntManager.Domain.Common;

namespace TantoOntManager.Domain.Observation;

public sealed class ObserverStartupState
{
    private readonly object _gate = new();
    private bool _started;
    private bool _coreReady;
    private bool _cookiesTransferred;
    private bool _cleaned;
    private bool _disposed;

    public bool Started
    {
        get { lock (_gate) { return _started; } }
    }

    public bool CoreReady
    {
        get { lock (_gate) { return _coreReady; } }
    }

    public bool CookiesTransferred
    {
        get { lock (_gate) { return _cookiesTransferred; } }
    }

    public bool Cleaned
    {
        get { lock (_gate) { return _cleaned; } }
    }

    public bool Disposed
    {
        get { lock (_gate) { return _disposed; } }
    }

    public bool TryBegin()
    {
        lock (_gate)
        {
            if (_started || _cleaned)
            {
                return false;
            }

            _started = true;
            return true;
        }
    }

    public void MarkCoreReady()
    {
        lock (_gate)
        {
            if (!_cleaned)
            {
                _coreReady = true;
            }
        }
    }

    public bool TryTransferCookies()
    {
        lock (_gate)
        {
            if (!_coreReady || _cleaned || _cookiesTransferred)
            {
                return false;
            }

            _cookiesTransferred = true;
            return true;
        }
    }

    public bool TryCleanup()
    {
        lock (_gate)
        {
            if (_cleaned)
            {
                return false;
            }

            _cleaned = true;
            return true;
        }
    }

    public bool TryDisposeWebView()
    {
        lock (_gate)
        {
            if (_disposed || !_coreReady)
            {
                return false;
            }

            _disposed = true;
            return true;
        }
    }
}

public sealed record ObserverInitializationResult(
    bool Succeeded,
    bool RuntimeMissing,
    bool RecognizedWebView2Failure,
    string OperatorMessage,
    string SanitizedLog,
    string ErrorCode,
    bool CookiesTransferred,
    int ConfigurationPostsSent,
    bool KeepMainProcess,
    bool CloseObserverOnly,
    bool EndAuthenticatedSession)
{
    public static ObserverInitializationResult Success()
        => new(
            true,
            false,
            false,
            string.Empty,
            string.Empty,
            string.Empty,
            true,
            0,
            true,
            false,
            false);
}

public static class ObserverInitializationGuard
{
    public const string RuntimeMissingOperatorMessage =
        "WebView2 Runtime x64 não localizado. Instale ou repare o componente e tente novamente.";

    public static ObserverInitializationResult FromException(Exception exception, bool cookiesTransferred)
    {
        var runtimeMissing = IsRuntimeMissing(exception);
        var recognized = IsRecognizedObserverOrWebView2(exception);
        return new ObserverInitializationResult(
            Succeeded: false,
            RuntimeMissing: runtimeMissing,
            RecognizedWebView2Failure: recognized,
            OperatorMessage: runtimeMissing || recognized
                ? RuntimeMissingOperatorMessage
                : "Falha ao iniciar o observador GET. A sessão autenticada foi preservada.",
            SanitizedLog: ToSanitizedLog(exception),
            ErrorCode: runtimeMissing
                ? ErrorCodes.ObservationWebView2RuntimeNotFound
                : ErrorCodes.ObservationInitializationFailed,
            CookiesTransferred: cookiesTransferred,
            ConfigurationPostsSent: 0,
            KeepMainProcess: true,
            CloseObserverOnly: true,
            EndAuthenticatedSession: false);
    }

    public static bool ShouldHandleOnDispatcher(Exception exception)
        => IsRecognizedObserverOrWebView2(exception);

    public static bool IsRuntimeMissing(Exception exception)
        => Flatten(exception).Any(item =>
            TypeNameContains(item, "WebView2RuntimeNotFound")
            || MessageContains(item, "compatible Webview2 Runtime")
            || MessageContains(item, "WebView2 Runtime")
            || (item is FileNotFoundException && MentionsWebView2(item)));

    public static bool IsRecognizedObserverOrWebView2(Exception exception)
        => Flatten(exception).Any(item =>
            IsRuntimeMissing(item)
            || TypeNameContains(item, "WebView2")
            || TypeNameContains(item, "CoreWebView2"));

    public static string ToSanitizedLog(Exception exception)
    {
        var parts = Flatten(exception)
            .Select(item => item.GetType().FullName + ": " + item.Message);
        return ObservationSanitizer.SanitizeText(string.Join(" | ", parts));
    }

    public static bool DestroyTemporaryFolder(string? folder)
        => IsolatedObserverCleanup.DestroyUserDataFolder(folder);

    private static IEnumerable<Exception> Flatten(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            yield return current;
        }
    }

    private static bool MentionsWebView2(Exception exception)
        => TypeNameContains(exception, "WebView2")
           || TypeNameContains(exception, "CoreWebView2")
           || MessageContains(exception, "WebView2")
           || MessageContains(exception, "Webview2");

    private static bool TypeNameContains(Exception exception, string token)
        => (exception.GetType().FullName ?? exception.GetType().Name)
            .Contains(token, StringComparison.OrdinalIgnoreCase);

    private static bool MessageContains(Exception exception, string token)
        => (exception.Message ?? string.Empty).Contains(token, StringComparison.OrdinalIgnoreCase);
}
