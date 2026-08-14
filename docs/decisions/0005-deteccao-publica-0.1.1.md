# ADR 0005 — Detecção pública 0.1.1 por pontuação

Status: aceito

A homologação real da F6201B retornou HTTPS 200 e título `F6201B`, mas a Fase 1.0 exigia o token `ZTE`/`ZXHN` na raiz. A página visível no Chrome contém `Welcome to F6201B` e `©2008-2025 ZTE Corporation`, possivelmente em frame.

A 0.1.1 pontua várias evidências, segue GET de frames/redirects no mesmo IP, e só identifica o modelo com fabricante + modelo. Login continua não mapeado.
