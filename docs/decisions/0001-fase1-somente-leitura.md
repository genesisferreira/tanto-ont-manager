# ADR 0001 — Somente leitura na Fase 1

Status: aceito

A primeira entrega não implementa gravação, reset, alteração de WAN/PPPoE/TR-069 nem autenticação real.

Motivo: o endpoint e o formato de login da F6201B ainda não foram homologados, a conta de laboratório tem privilégios parciais, e o preset parece embutido no firmware. Inventar URLs de escrita seria inseguro e fora do escopo.

# ADR 0002 — Confiança TLS limitada ao IP selecionado

Status: aceito

ONTs de laboratório usam HTTPS self-signed. A validação global do Windows permanece ativa. Um `SocketsHttpHandler` por probe aceita o certificado apenas quando o IP remoto é o escolhido pelo operador e o aviso está visível.

# ADR 0003 — Sem varredura de rede

Status: aceito

Várias ONTs compartilham o mesmo IP padrão. A descoberta testa somente `192.168.100.1`, `192.168.1.1` ou um IP informado. Não há varredura de sub-rede.

# ADR 0004 — Lote apenas documentado

Status: aceito

O fluxo CSV → detectar → backup → preset → validar existe como interface e documentação. Nenhuma etapa de gravação está ligada à UI.
