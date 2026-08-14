# Contrato do adaptador de ONT

A interface de leitura é `IOntDeviceAdapter`:

- `ProbeAsync`
- `ReadIdentityAsync`
- `ReadDiagnosticsAsync`
- `ReadCapabilitiesAsync`

Não existem `ExecuteCommand`, `RunScript` ou `PostRawRequest`.

## Autenticação

`IOntAuthenticationAdapter` é separado. Na Fase 1, o adaptador ZTE retorna `AuthenticationMethodNotMapped` e `CanAttemptAuthentication` é `false`. Nenhuma credencial é transmitida.

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

- Identifica F6201B só com evidência pública suficiente (título/corpo/marcadores ZXHN/ZTE/F6201B).
- F6600P e F670L têm IDs preparados, sem detector específico nesta entrega.
- Parser baseado em HTML público, tolerante a mudanças pequenas, sem gravar configuração.
