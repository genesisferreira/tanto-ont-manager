# ADR 0006 — Autenticação autorizada F6201B 0.1.2

Status: aceito

A página pública da F6201B não usa `<form action>`. O login observado é AJAX:

1. GET `/?_type=loginData&_tag=login_entry` (token)
2. GET `/?_type=loginData&_tag=login_token` (challenge XML)
3. POST único `/?_type=loginData&_tag=login_entry` com `action=login`, `Username`, `Password=SHA-256(senha+challenge)` e `_sessionTOKEN`

Somente esse POST é permitido. Logout observado (`logout_entry`) não é chamado: encerrar sessão descarta cookies em memória. Leituras internas usam GET `/?_type=menuView&_tag=` apenas para tags descobertas na UI autenticada.
