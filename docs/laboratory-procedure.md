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

## Resultado esperado nesta fase

- Resposta HTTPS/HTTP do endereço testado
- Reconhecimento público de ZTE F6201B quando o título/marcadores existirem
- Hardware, firmware, boot, serial, MAC, PON, temperatura, potência e WAN como “não disponíveis na interface pública”, salvo se aparecerem na página pública
- Login: `AuthenticationMethodNotMapped`

## Proibido no laboratório desta fase

- Factory reset pelo aplicativo
- Alterar WAN/VLAN/PPPoE/TR-069
- Procurar senhas
- Ativar Telnet/SSH
- Enviar requisições a caminhos não observados na interface pública
