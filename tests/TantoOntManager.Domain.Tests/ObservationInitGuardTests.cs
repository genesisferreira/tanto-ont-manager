using FluentAssertions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.Domain.Tests;

public sealed class ObserverInitializationGuardTests
{
    [Fact]
    public void CreateAsync_runtime_missing_keeps_main_process_and_closes_only_observer()
    {
        var exception = new WebView2RuntimeNotFoundException(
            "Couldn't find a compatible Webview2 Runtime installation to host WebViews.",
            new FileNotFoundException("O sistema não pode encontrar o arquivo especificado. (0x80070002)"));

        var result = ObserverInitializationGuard.FromException(exception, cookiesTransferred: false);

        result.Succeeded.Should().BeFalse();
        result.RuntimeMissing.Should().BeTrue();
        result.KeepMainProcess.Should().BeTrue();
        result.CloseObserverOnly.Should().BeTrue();
        result.EndAuthenticatedSession.Should().BeFalse();
        result.CookiesTransferred.Should().BeFalse();
        result.ConfigurationPostsSent.Should().Be(0);
        result.ErrorCode.Should().Be(ErrorCodes.ObservationWebView2RuntimeNotFound);
        result.OperatorMessage.Should().Be(ObserverInitializationGuard.RuntimeMissingOperatorMessage);
    }

    [Fact]
    public void Cookies_are_not_transferred_before_core_is_ready()
    {
        var state = new ObserverStartupState();
        state.TryBegin().Should().BeTrue();
        state.TryTransferCookies().Should().BeFalse();
        state.CookiesTransferred.Should().BeFalse();
        state.MarkCoreReady();
        state.TryTransferCookies().Should().BeTrue();
        state.TryTransferCookies().Should().BeFalse();
    }

    [Fact]
    public void Failed_init_cleans_empty_observer_webview_folder()
    {
        var root = Path.Combine(Path.GetTempPath(), "tanto-obs-" + Guid.NewGuid().ToString("N"), "observer-webview");
        var folder = Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        Directory.Exists(folder).Should().BeTrue();

        var exception = new FileNotFoundException("Couldn't find a compatible Webview2 Runtime installation to host WebViews.");
        var result = ObserverInitializationGuard.FromException(exception, cookiesTransferred: false);
        result.CookiesTransferred.Should().BeFalse();
        result.ConfigurationPostsSent.Should().Be(0);

        ObserverInitializationGuard.DestroyTemporaryFolder(folder).Should().BeTrue();
        Directory.Exists(folder).Should().BeFalse();
        Directory.Exists(root).Should().BeFalse();
    }

    [Fact]
    public void Sanitized_log_omits_cookie_token_and_password()
    {
        var exception = new WebView2RuntimeNotFoundException(
            "cookie=SID_HTTPS_=abc123; _sessionTOKEN=sekrit; password=lab-pass",
            new FileNotFoundException("Authorization=Bearer secret-token"));
        var log = ObserverInitializationGuard.ToSanitizedLog(exception);
        log.Should().NotContain("abc123");
        log.Should().NotContain("sekrit");
        log.Should().NotContain("lab-pass");
        log.Should().NotContain("secret-token");
        ObservationSanitizer.LooksUnsanitized(log).Should().BeFalse();
    }

    [Fact]
    public void Dispatcher_does_not_handle_unknown_exceptions()
    {
        ObserverInitializationGuard.ShouldHandleOnDispatcher(new InvalidOperationException("falha desconhecida"))
            .Should().BeFalse();
        ObserverInitializationGuard.ShouldHandleOnDispatcher(new FileNotFoundException("missing-config.json"))
            .Should().BeFalse();
        ObserverInitializationGuard.ShouldHandleOnDispatcher(
                new WebView2RuntimeNotFoundException("Couldn't find a compatible Webview2 Runtime installation to host WebViews."))
            .Should().BeTrue();
    }

    [Fact]
    public void Startup_state_prevents_double_begin_cleanup_and_dispose()
    {
        var state = new ObserverStartupState();
        state.TryBegin().Should().BeTrue();
        state.TryBegin().Should().BeFalse();
        state.MarkCoreReady();
        state.TryCleanup().Should().BeTrue();
        state.TryCleanup().Should().BeFalse();
        state.TryDisposeWebView().Should().BeTrue();
        state.TryDisposeWebView().Should().BeFalse();
        state.TryTransferCookies().Should().BeFalse();
    }

    private sealed class WebView2RuntimeNotFoundException : Exception
    {
        public WebView2RuntimeNotFoundException(string message, Exception? inner = null)
            : base(message, inner)
        {
        }
    }
}
