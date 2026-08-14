using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Extensions.Logging;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Adapters;
using TantoOntManager.Domain.Common;
using TantoOntManager.Domain.Devices;
using TantoOntManager.Domain.Network;
using TantoOntManager.Domain.Sessions;

namespace TantoOntManager.DeviceAdapters.Zte;

public sealed class ZteF6201BV9310P8N1AuthenticationAdapter : IOntAuthenticationAdapter
{
    public const string Id = F6201BV9310P8N1AuthContract.AdapterId;

    private readonly IBoundOntTransportFactory _transportFactory;
    private readonly IOntAuthSessionStore _sessionStore;
    private readonly ILogger<ZteF6201BV9310P8N1AuthenticationAdapter> _logger;

    public ZteF6201BV9310P8N1AuthenticationAdapter(
        IBoundOntTransportFactory transportFactory,
        IOntAuthSessionStore sessionStore,
        ILogger<ZteF6201BV9310P8N1AuthenticationAdapter> logger)
    {
        _transportFactory = transportFactory;
        _sessionStore = sessionStore;
        _logger = logger;
    }

    public string AdapterId => Id;

    public bool CanAttemptAuthentication(AdapterProbeResult probe)
        => probe.Matched
           && probe.HttpsUsed
           && probe.LoginFormVisible
           && probe.Confidence >= 0.55
           && string.Equals(probe.Manufacturer, ManufacturerNames.Zte, StringComparison.Ordinal)
           && string.Equals(probe.Model, DeviceModelIds.ZteF6201B, StringComparison.Ordinal);

    public async Task<AuthenticationResult> AuthenticateAsync(
        OntEndpoint endpoint,
        AdapterProbeResult probe,
        DeviceCredentials credentials,
        string? pinnedCertificateSha256,
        CancellationToken cancellationToken)
    {
        var started = Stopwatch.StartNew();
        _logger.LogInformation(
            "Início da autenticação adapter={Adapter} target={Target}",
            AdapterId,
            endpoint.Address);

        if (!CanAttemptAuthentication(probe) || !endpoint.Address.Equals(probe.Endpoint.Address))
        {
            return Fail(
                AuthSessionState.ContractIncompatible,
                ErrorCodes.ContractIncompatible,
                "O contrato de autenticação não se aplica a este alvo.",
                started.Elapsed);
        }

        var transport = _transportFactory.Create(endpoint, pinnedCertificateSha256);
        try
        {
            var home = await transport.GetAsync("/", cancellationToken);
            if (!home.Succeeded)
            {
                return TransportFail(home, started.Elapsed, transport);
            }

            if (!F6201BV9310P8N1AuthContract.PublicPageMatchesContract(home.Body))
            {
                return Fail(
                    AuthSessionState.ContractIncompatible,
                    ErrorCodes.ContractIncompatible,
                    "A página pública não contém o contrato de login homologado da F6201B V9.3.10P8N1.",
                    started.Elapsed,
                    transport,
                    home);
            }

            var bootstrap = await transport.GetAsync(F6201BV9310P8N1AuthContract.LoginPathAndQuery, cancellationToken);
            if (!bootstrap.Succeeded)
            {
                return TransportFail(bootstrap, started.Elapsed, transport);
            }

            var bootstrapParsed = F6201BV9310P8N1LoginParser.ParseBootstrap(bootstrap.Body);
            if (!bootstrapParsed.TokenPresent)
            {
                return Fail(
                    AuthSessionState.ControlledFailure,
                    ErrorCodes.AuthTokenMissing,
                    "O token de sessão inicial não foi obtido. Nenhum POST foi enviado.",
                    started.Elapsed,
                    transport,
                    bootstrap);
            }

            var challenge = await transport.GetAsync(F6201BV9310P8N1AuthContract.TokenPathAndQuery, cancellationToken);
            if (!challenge.Succeeded)
            {
                return TransportFail(challenge, started.Elapsed, transport);
            }

            var challengeText = F6201BV9310P8N1LoginParser.ReadChallenge(challenge.Body);
            if (string.IsNullOrWhiteSpace(challengeText))
            {
                return Fail(
                    AuthSessionState.ControlledFailure,
                    ErrorCodes.AuthTokenMissing,
                    "O challenge de login não foi obtido. Nenhum POST foi enviado.",
                    started.Elapsed,
                    transport,
                    challenge);
            }

            var username = credentials.Username;
            var password = ReadPassword(credentials.Password);
            string hash;
            try
            {
                hash = F6201BV9310P8N1LoginParser.HashPassword(password, challengeText);
            }
            finally
            {
                password = string.Empty;
            }

            var token = ReadSessionToken(bootstrap.Body);
            var form = new Dictionary<string, string>
            {
                ["action"] = "login",
                ["Username"] = username,
                ["Password"] = hash,
                ["_sessionTOKEN"] = token
            };
            hash = string.Empty;
            token = string.Empty;

            var post = await transport.PostLoginFormAsync(form, cancellationToken);
            form["Password"] = string.Empty;
            form["_sessionTOKEN"] = string.Empty;
            form["Username"] = string.Empty;

            if (!post.Succeeded)
            {
                return TransportFail(post, started.Elapsed, transport);
            }

            var parsed = F6201BV9310P8N1LoginParser.ParsePost(post.Body);
            if (parsed.LooksExpired)
            {
                return Fail(
                    AuthSessionState.ControlledFailure,
                    ErrorCodes.AuthTokenExpired,
                    "O token de login expirou. A tentativa não foi repetida.",
                    started.Elapsed,
                    transport,
                    post);
            }

            if (!parsed.RefreshRequested)
            {
                return Fail(
                    AuthSessionState.CredentialRejected,
                    ErrorCodes.CredentialRejected,
                    "A ONT recusou a credencial. Usuário e senha não são diferenciados.",
                    started.Elapsed,
                    transport,
                    post);
            }

            if (post.StatusCode != 200 || !transport.HasSessionCookie)
            {
                return Fail(
                    AuthSessionState.ControlledFailure,
                    ErrorCodes.UnexpectedFailure,
                    "O login não reuniu evidências suficientes de sessão.",
                    started.Elapsed,
                    transport,
                    post);
            }

            var authenticatedHome = await transport.GetAsync("/", cancellationToken);
            if (!authenticatedHome.Succeeded)
            {
                return TransportFail(authenticatedHome, started.Elapsed, transport);
            }

            if (F6201BHtmlText.LooksLikeSessionExpired(authenticatedHome.Body))
            {
                return Fail(
                    AuthSessionState.SessionExpired,
                    ErrorCodes.SessionExpired,
                    "A sessão autenticada expirou imediatamente após o login.",
                    started.Elapsed,
                    transport,
                    authenticatedHome);
            }

            var read = await F6201BAuthenticatedSafeReader.ReadAsync(
                transport,
                authenticatedHome.Body,
                "/",
                authenticatedHome,
                cancellationToken);

            if (read.SessionExpired && read.Pages.Count <= 1)
            {
                return Fail(
                    AuthSessionState.SessionExpired,
                    ErrorCodes.SessionExpired,
                    "A sessão autenticada expirou durante a leitura GET.",
                    started.Elapsed,
                    transport,
                    authenticatedHome);
            }

            var pageBodies = read.Pages.ToArray();
            var device = F6201BV9310P8N1DeviceInformationParser.Parse(pageBodies);
            var pon = F6201BV9310P8N1PonParser.Parse(pageBodies);
            var wan = F6201BV9310P8N1WanParser.Parse(pageBodies);
            var identity = F6201BV9310P8N1AuthenticatedPageParser.ToIdentity(
                ManufacturerNames.Zte,
                DeviceModelIds.ZteF6201B,
                device);

            if (!F6201BV9310P8N1AuthenticatedPageParser.FirmwareMatchesWhenPresent(identity))
            {
                return Fail(
                    AuthSessionState.ContractIncompatible,
                    ErrorCodes.ContractIncompatible,
                    "A firmware lida não é a V9.3.10P8N1 homologada. A sessão foi encerrada.",
                    started.Elapsed,
                    transport,
                    authenticatedHome);
            }

            var diagnostics = F6201BV9310P8N1AuthenticatedPageParser.ToDiagnostics(pon, wan);
            var evidence = device.Evidence.Concat(pon.Evidence).Concat(wan.Evidence).ToList();
            var snapshot = new AuthenticatedReadSnapshot(
                identity,
                diagnostics,
                read.PageNames,
                transport.PostCount,
                authenticatedHome.RedirectCount,
                post.StatusCode.ToString(),
                authenticatedHome.SanitizedBodySha256,
                started.Elapsed,
                AdapterId,
                read.Inventory,
                evidence,
                transport.LoginPostCount,
                transport.LogoutPostCount,
                transport.ConfigPostCount);

            var session = AuthorizedDeviceSession.Authenticated(
                endpoint,
                F6201BV9310P8N1AuthContract.AuthenticationMethod,
                transport.ObservedCertificateSha256);

            _sessionStore.Remember(transport, session, snapshot);

            _logger.LogInformation(
                "Fim da autenticação resultado={Result} status={Status} posts={Posts} redirects={Redirects} paginas={Pages} duracao={Duration} hash={Hash}",
                AuthSessionState.AuthenticatedReadOnly,
                post.StatusCode,
                snapshot.PostCount,
                post.RedirectCount,
                read.PageNames.Count,
                started.Elapsed,
                snapshot.LastSanitizedHash);

            return AuthenticationResult.Succeeded(
                session,
                snapshot,
                post.StatusCode,
                F6201BV9310P8N1AuthContract.LoginPathAndQuery,
                started.Elapsed);
        }
        catch (OperationCanceledException)
        {
            var posts = transport.PostCount;
            transport.ClearCookiesAndState();
            transport.Dispose();
            return Fail(
                AuthSessionState.ControlledFailure,
                ErrorCodes.ProbeTimeout,
                "A autenticação excedeu o tempo limite. Nenhuma repetição automática foi feita.",
                started.Elapsed,
                postCount: posts);
        }
        finally
        {
            credentials.Dispose();
        }
    }

    private static AuthenticationResult TransportFail(BoundHttpResult result, TimeSpan duration, IBoundOntTransport transport)
    {
        var code = result.Error?.Code ?? ErrorCodes.UnexpectedFailure;
        var state = code switch
        {
            ErrorCodes.CertificateChanged => AuthSessionState.CertificateChanged,
            ErrorCodes.SessionExpired => AuthSessionState.SessionExpired,
            _ => AuthSessionState.ControlledFailure
        };

        return Fail(state, code, result.Error?.Message ?? "Falha controlada na sessão autenticada.", duration, transport, result);
    }

    private static AuthenticationResult Fail(
        AuthSessionState state,
        string code,
        string message,
        TimeSpan duration,
        IBoundOntTransport? transport = null,
        BoundHttpResult? last = null,
        int postCount = 0)
    {
        var posts = transport?.PostCount ?? postCount;
        var redirects = last?.RedirectCount ?? 0;
        var status = last?.StatusCode;
        var hash = last?.SanitizedBodySha256;
        var masked = last?.FinalUri is { Length: > 0 } uri ? SafeMask(uri) : null;
        transport?.ClearCookiesAndState();
        transport?.Dispose();
        return AuthenticationResult.Failed(
            state,
            Error.Create(code, message),
            posts,
            redirects,
            status,
            masked,
            hash,
            duration);
    }

    private static string SafeMask(string uri)
        => Uri.TryCreate(uri, UriKind.Absolute, out var parsed)
            ? F6201BV9310P8N1AuthContract.MaskUri(parsed)
            : "/";

    private static string ReadPassword(SecureString password)
    {
        if (password.Length == 0)
        {
            return string.Empty;
        }

        var pointer = Marshal.SecureStringToGlobalAllocUnicode(password);
        try
        {
            return Marshal.PtrToStringUni(pointer) ?? string.Empty;
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(pointer);
        }
    }

    private static string ReadSessionToken(string json)
    {
        var match = System.Text.RegularExpressions.Regex.Match(
            json,
            "\"sess_token\"\\s*:\\s*\"([^\"]*)\"");
        return match.Success ? match.Groups[1].Value : string.Empty;
    }
}
