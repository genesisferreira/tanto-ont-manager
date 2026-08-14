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
10. Após o login, confira as abas Dispositivo, PON e WAN. Use `Exportar diagnóstico autenticado` e confira a inspeção do ZIP.
11. Clique em `Encerrar sessão` ao terminar. O aplicativo envia no máximo um POST de logout oficial e descarta os cookies.

## Observação passiva de GETs (0.1.6.1-lab)

1. Confirme o Microsoft Edge WebView2 Runtime x64 instalado. Sem ele, o observador fecha só a janela própria e preserva a sessão autenticada.
2. Com a F6201B autenticada em modo laboratório, clique em `Observar navegação GET` e confirme.
3. No WebView2 isolado, feche o baseline do shell e use os botões Device / PON / WAN Status / WAN Config.
4. Durante os 20 s de cada captura, navegue **manualmente** na tela correspondente da ONT.
5. Confira os contadores: POST de configuração deve permanecer 0.
6. `Exportar observação sanitizada` e inspecione IncludesCookies/Credentials/Tokens/RawAuthenticatedBody = false.
7. `Promover contrato de leitura` gera só um JSON local em `diagnostics/proposals`; o adaptador F6201B não muda.
8. Feche o observador: a pasta WebView2 e os cookies temporários são destruídos.

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
