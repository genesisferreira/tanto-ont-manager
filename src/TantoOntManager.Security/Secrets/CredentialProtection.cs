using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace TantoOntManager.Security.Secrets;

[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector
{
    public byte[] Protect(byte[] plaintext)
        => ProtectedData.Protect(plaintext, optionalEntropy: null, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] protectedBytes)
        => ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
}
