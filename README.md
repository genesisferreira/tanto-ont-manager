# Tanto ONT Manager

Ferramenta interna da **Tanto Telecom** para identificação, diagnóstico e, no futuro, padronização de ONTs conectadas ao computador por cabo de rede.

A Fase 1 é **somente leitura**. A versão `0.1.8-lab` lê automaticamente Device, PON, WAN Status e WAN Config da F6201B V9.3.10P8N1 após o login homologado, usando somente GETs observados (`menuView` imediatamente antes de `menuData`) e aliases XML lua desta firmware. A Fase 2A permite mapear o contrato de gravação WAN/PPPoE no WebView2 isolado, interceptando e **bloqueando** o primeiro POST/PUT/PATCH/DELETE candidato **antes da rede**. Não altera WAN, PPPoE, VLAN, firmware nem a placa Ethernet.

## Status da Fase 1

- Modo de operação: `Laboratório — somente leitura`
- Versão: `0.1.8-lab`
- Processamento: uma ONT por vez
- Modelos iniciais previstos: ZTE ZXHN F6201B, F6600P, F670L
- Detector público: F6201B por pontuação de evidências (título, Welcome to F6201B, ZTE Corporation, rodapé)
- Autenticação autorizada: `ZteF6201BV9310P8N1AuthenticationAdapter` (um POST no endpoint observado)
- Diagnóstico público e autenticado sanitizados exportáveis
- Modelo futuro: Zyxel PM5301-T7 (ainda sem adaptador)

## Requisitos

- Windows 10/11
- .NET 8 SDK
- Microsoft Edge WebView2 Runtime (Evergreen)
- Cabo Ethernet até a ONT
- IPv4 na mesma sub-rede do equipamento

## Como executar

```powershell
cd C:\Users\genes\tanto-ont-manager
dotnet restore
dotnet build
dotnet test
dotnet run --project src/TantoOntManager.App/TantoOntManager.App.csproj
```

Logs sanitizados:

`%LocalAppData%\TantoTelecom\TantoOntManager\logs\`

Diagnósticos públicos:

`%LocalAppData%\TantoTelecom\TantoOntManager\diagnostics\`

## O que esta entrega faz

- Lista adaptadores Ethernet e o IPv4 atual
- Mostra se há link físico
- Testa somente `192.168.100.1`, `192.168.1.1` ou um IP informado pelo operador
- Verifica ICMP, HTTPS e HTTP com timeout curto
- Reconhece marcadores públicos da interface ZTE F6201B (incluindo título `F6201B`, `Welcome to F6201B` e `ZTE Corporation`)
- Segue redirects e frames públicos no mesmo IP, só com GET
- Mostra status HTTP, título, tamanho, hash curto, confiança e evidências
- Exporta ZIP sanitizado da página pública
- Login da F6201B V9.3.10P8N1: um POST no endpoint observado, cookies só em memória
- Observação passiva dos GETs dinâmicos em WebView2 isolado (`Observar navegação GET`)
- Mapeamento bloqueado do contrato de gravação WAN/PPPoE (Fase 2A): captura um candidato, sanitiza e cancela o envio
- Leitura autenticada GET por tags evidenciadas e classificadas SafeRead
- Encerrar sessão envia no máximo um POST de logout oficial e descarta cookies
- Exporta diagnóstico autenticado sanitizado, com inspeção do ZIP

## O que esta entrega não faz

- Não altera WAN, VLAN, PPPoE ou TR-069
- Não faz factory reset nem troca firmware
- Não adivinha senhas e não usa credenciais de etiquetas
- Não ativa Telnet/SSH
- Não varre a rede
- Não desabilita a validação TLS do Windows
- Não declara o contrato de escrita como homologado
- Não declara suporte a configuração PPPoE

## Arquitetura

Ver `docs/architecture.md`, `docs/security.md`, `docs/device-adapter-contract.md` e `docs/laboratory-procedure.md`.
