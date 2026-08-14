using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BV9310P8N1Logout
{
    public static async Task<LogoutResult> ExecuteAsync(
        IBoundOntTransport transport,
        CancellationToken cancellationToken)
    {
        var loginPosts = transport.LoginPostCount;
        var form = new Dictionary<string, string>
        {
            ["IF_LogOff"] = "1",
            ["_sessionTOKEN"] = transport.SessionToken ?? string.Empty
        };

        BoundHttpResult response;
        try
        {
            response = await transport.PostLogoutFormAsync(form, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            transport.ClearCookiesAndState("logout-timeout");
            return LogoutResult.LocalOnly(loginPosts, transport.LogoutPostCount, ErrorCodes.ProbeTimeout);
        }
        finally
        {
            form["_sessionTOKEN"] = string.Empty;
        }

        transport.ClearCookiesAndState("logout");

        if (LooksSuccessful(response))
        {
            return LogoutResult.RemoteConfirmed(loginPosts, transport.LogoutPostCount);
        }

        return LogoutResult.LocalOnly(
            loginPosts,
            transport.LogoutPostCount,
            response.Error?.Code ?? ErrorCodes.UnexpectedFailure);
    }

    public static bool LooksSuccessful(BoundHttpResult response)
    {
        if (!response.Succeeded || response.StatusCode != 200)
        {
            return false;
        }

        var body = response.Body ?? string.Empty;
        if (string.IsNullOrWhiteSpace(body))
        {
            return true;
        }

        if (body.Contains("\"need_refresh\":true", StringComparison.OrdinalIgnoreCase)
            || body.Contains("\"login_need_refresh\":true", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (LooksLikeStillAuthenticatedShell(body))
        {
            return false;
        }

        return LooksLikeZteLogoutAck(body) || F6201BHtmlText.LooksLikeLoginPage(body);
    }

    private static bool LooksLikeStillAuthenticatedShell(string body)
        => F6201BHtmlText.Classify(body) == AuthenticatedPageKind.AuthenticatedPage;

    private static bool LooksLikeZteLogoutAck(string body)
    {
        if (body.Contains("<html", StringComparison.OrdinalIgnoreCase)
            && !F6201BHtmlText.LooksLikeLoginPage(body))
        {
            return false;
        }

        if (body.Contains("This page has expired, please refresh and try again.", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (body.Contains("need_refresh", StringComparison.OrdinalIgnoreCase)
            || body.Contains("sess_token", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var trimmed = body.Trim();
        return trimmed.StartsWith('{') && trimmed.EndsWith('}');
    }
}
