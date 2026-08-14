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
            transport.ClearCookiesAndState();
            return LogoutResult.LocalOnly(loginPosts, transport.LogoutPostCount, ErrorCodes.ProbeTimeout);
        }
        finally
        {
            form["_sessionTOKEN"] = string.Empty;
        }

        transport.ClearCookiesAndState();

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
        if (body.Contains("This page has expired, please refresh and try again.", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(body))
        {
            return true;
        }

        if (body.Contains("\"need_refresh\":true", StringComparison.OrdinalIgnoreCase)
            || body.Contains("\"login_need_refresh\":true", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return !body.Contains("need_refresh", StringComparison.OrdinalIgnoreCase)
               && !F6201BHtmlText.LooksLikeSessionExpired(body);
    }
}
