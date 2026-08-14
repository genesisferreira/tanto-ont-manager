# Procedimento de laboratório — Fase 1

## Preparação

1. Conecte **uma** ONT por cabo Ethernet ao computador.
2. Não conecte várias ONTs ao mesmo tempo: o IP padrão se repete.
3. Abra o Tanto ONT Manager.
4. Confirme o indicador `Laboratório — somente leitura`.

## Rede

Para `192.168.100.1` (F6201B de laboratório):

```text
IP sugerido: 192.168.100.10
Máscara: 255.255.255.0
Gateway: 192.168.100.1
```

Para `192.168.1.1`:

```text
IP sugerido: 192.168.1.10
Máscara: 255.255.255.0
Gateway: 192.168.1.1
```

O aplicativo **não** aplica essa configuração. Ajuste a placa manualmente, se necessário.

## Detecção

1. Selecione a interface Ethernet.
2. Confirme o IPv4 atual e o estado do cabo.
3. Selecione o IP conhecido ou informe um IP personalizado.
4. Mantenha o aviso de certificado local visível.
5. Clique em `Testar conexão` e depois em `Detectar ONT`.
6. Confira confiança, evidências, status HTTPS e hash curto.
7. Clique em `Exportar diagnóstico público` se precisar arquivar a página pública.
8. Clique em `Exportar diagnóstico público` se precisar arquivar a página pública.
9. Se a F6201B foi identificada com confiança suficiente, informe a credencial da etiqueta e clique **uma vez** em `Login`.
10. Após o login, use `Exportar diagnóstico autenticado` se precisar arquivar identidade/PON/WAN sanitizados.
11. Clique em `Encerrar sessão` ao terminar. Nenhum POST de logout é enviado.

## Resultado esperado nesta fase

- Resposta HTTPS do endereço testado (HTTP pode estar indisponível)
- Identificação pública `ZTE ZXHN F6201B` com evidências suficientes
- Login homologado somente para firmware `V9.3.10P8N1`: um POST, cookies em memória
- Hardware, firmware, boot, PON, temperatura, potência e nomes WAN lidos por GET após autenticação, quando presentes nas páginas allowlist
- Serial e MAC mascarados na UI e na exportação

## Proibido no laboratório desta fase

- Factory reset pelo aplicativo
- Alterar WAN/VLAN/PPPoE/TR-069
- Procurar senhas
- Ativar Telnet/SSH
- Enviar requisições a caminhos não observados na interface pública
