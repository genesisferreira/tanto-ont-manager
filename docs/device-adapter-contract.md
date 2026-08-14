# Contrato do adaptador de ONT

A interface de leitura é `IOntDeviceAdapter`:

- `ProbeAsync`
- `ReadIdentityAsync`
- `ReadDiagnosticsAsync`
- `ReadCapabilitiesAsync`

Não existem `ExecuteCommand`, `RunScript` ou `PostRawRequest`.

## Autenticação

`IOntAuthenticationAdapter` é separado. A F6201B V9.3.10P8N1 usa `ZteF6201BV9310P8N1AuthenticationAdapter`. Outros modelos ZTE continuam `AuthenticationMethodNotMapped`.

## Escrita futura

Contratos vazios e explícitos:

- `IOntWriteAdapter`
- `IOntBackupAdapter`
- `IOntPresetAdapter`

Antes de implementar qualquer gravação:

1. desativada por padrão;
2. adaptador homologado para modelo e firmware;
3. backup pelo mecanismo oficial, se existir;
4. validação antes e depois;
5. rollback ou procedimento documentado;
6. confirmação explícita do operador;
7. auditoria sem senha em texto aberto.

## Detector ZTE atual

- Identifica F6201B por pontuação de evidências públicas (não por um único texto).
- Evidências: `ZTE Corporation`, `Welcome to F6201B`, `F6201B`, marca `ZTE`, título, rodapé `©2008-2025 ZTE Corporation`.
- Segue redirects e frames públicos no mesmo IP, somente GET.
- F6600P e F670L têm IDs preparados; conflito de modelos não identifica.
- Gravação e login genérico ZTE não estão mapeados.
- Login específico: F6201B firmware `V9.3.10P8N1`, um POST em `/?_type=loginData&_tag=login_entry`.
