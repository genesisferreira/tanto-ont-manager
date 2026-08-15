# Arquitetura

## Objetivo

Um único aplicativo Windows para o técnico, com adaptadores internos por fabricante, modelo e firmware.

```text
App (WPF / MVVM)
  -> Application (casos de uso)
    -> DeviceAdapters (somente leitura na Fase 1)
    -> Networking (descoberta e probe)
    -> Security (TLS local, DPAPI, sanitização)
    -> Domain (regras e resultados tipados)
```

## Projetos

| Projeto | Responsabilidade |
|---|---|
| `TantoOntManager.App` | WPF, views, viewmodels, DI de composição |
| `TantoOntManager.Application` | Detecção, teste de conexão, autenticação estrutural, lote futuro |
| `TantoOntManager.Domain` | Entidades, VOs, erros, estados, máscaras |
| `TantoOntManager.Networking` | Ethernet, ping, HTTP/HTTPS, sem alterar a NIC |
| `TantoOntManager.DeviceAdapters.Abstractions` | Contrato de probe/leitura |
| `TantoOntManager.DeviceAdapters.Zte` | Detector público F6201B e login versionado V9.3.10P8N1 |
| `TantoOntManager.Security` | Certificado local, DPAPI, sanitização |
| `TantoOntManager.Infrastructure` | Serilog, DI, auditoria |

## Regras da Fase 1

- Uma ONT por vez, porque o IP padrão se repete.
- Somente GET da raiz pública na detecção (`/` HTTP ou HTTPS).
- Login da F6201B: um POST de login e, no encerramento explícito, no máximo um POST de logout; leitura automática Device/PON/WAN por GET homologado na allowlist.
- Fase 2A: observação de gravação WAN/PPPoE no WebView2 isolado; POST/PUT/PATCH/DELETE são interceptados e bloqueados antes da rede. A allowlist de escrita permanece vazia.
- Sem métodos genéricos perigosos (`ExecuteCommand`, `PostRawRequest`).
- Escrita futura exige adaptador homologado, backup oficial, validação, rollback, confirmação e auditoria.

## Dependências externas e justificativa

- `Microsoft.Extensions.*`: DI, logging e HttpClientFactory, conforme stack definida.
- `Serilog` + sink de arquivo: logs rotativos com sanitização.
- `System.Security.Cryptography.ProtectedData`: DPAPI do Windows.
- `xUnit` e `FluentAssertions`: testes.
- SQLite não foi adicionado: histórico persistente ainda não é necessário.

HttpClientFactory está registrado. O probe da ONT usa `SocketsHttpHandler` por chamada para aplicar confiança TLS somente ao IP selecionado, sem callback global.
