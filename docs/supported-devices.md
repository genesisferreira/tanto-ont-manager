# Equipamentos suportados

## Fase 1 — detector público

| Fabricante | Modelo | Status | Observação |
|---|---|---|---|
| ZTE | ZXHN F6201B | Detecção pública inicial | IP de laboratório `192.168.100.1`, HTTPS, certificado self-signed |
| ZTE | ZXHN F6600P | Estrutura apenas | Sem detector específico |
| ZTE | ZXHN F670L | Estrutura apenas | Sem detector específico |
| Zyxel | PM5301-T7 | Futuro | Sem adaptador |

## Dados confirmados em laboratório (F6201B)

- Hardware: `V9.3.12`
- Software: `V9.3.10P8N1`
- Boot: `V9.3.10P10N6`
- Após reset, o preset voltou automaticamente
- Perfis observados na UI autenticada do equipamento (ainda **não lidos pelo app**, porque exigem login não mapeado):
  - `HSI_TR069` — INTERNET_TR069, VLAN 210
  - `VOIP_IPTV` — INTERNET_VoIP, VLAN 220
- Sem PPPoE visível na conta atual
- Sem exportação/importação encontrada
- Conta de laboratório com privilégios parciais

Esses perfis **não** são gravados nem reaplicados nesta fase. PPPoE não é suportado como configuração.

## Sem fibra

Observado no equipamento, ainda não lido pelo app:

- ONU State: O1/Initial State
- WAN disconnected / No Carrier
- IPs `0.0.0.0`
