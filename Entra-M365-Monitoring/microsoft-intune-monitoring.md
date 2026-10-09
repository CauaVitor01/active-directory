# Monitoramento do Microsoft Intune — Detecção de Ameaças

> 🎞️ **Apresentação (deck) com o resumo desta documentação:** [abrir no Gemini](https://share.gemini.google/1mEtVFvY81LI)
>
> 📎 **Evidências:** as capturas de tela e os resultados das consultas estão no PDF de mesmo nome (`microsoft_intune_monitoring.pdf`), que acompanha este arquivo.

Olá, meu nome é Cauã. Esta documentação resume o que aprendi na sala de **Monitoramento do Microsoft Intune** do TryHackMe: como a plataforma funciona, como um invasor pode transformá-la em arma e como detectar e prevenir esse abuso usando o Splunk e os logs do próprio host.

## Resumo rápido

- O Intune é uma plataforma de **MDM** em nuvem. Quem controla o console controla **todos os dispositivos inscritos**.
- Um único administrador comprometido já basta para um estrago enorme, como no ataque ao **Stryker** (~80.000 dispositivos apagados).
- Há três formas principais de abuso: **limpeza remota**, **scripts de plataforma** e **implantação de aplicativos**.
- A detecção acontece em três pontos: **login no portal**, **ação no Intune** e **rastros no host**.
- A melhor defesa é reduzir quem pode fazer o quê: contas protegidas, **funções personalizadas**, **tags de escopo** e **aprovação de vários administradores**.

---

## 1. O Intune em poucas palavras

O Intune permite auditar e controlar remotamente dispositivos Windows, Linux, macOS e móveis: política de senha, criptografia de disco, configurações do SO e lista de permissões de aplicativos. Concorrentes conhecidos: Jamf, JumpCloud, Atera e ManageEngine.

**Como entra em ação**
- Os dispositivos são inscritos manualmente ou de forma remota (ADE no macOS, serviços do Google Play no Android).
- No Windows basta **entrar com o e-mail corporativo**: o dispositivo aparece no Entra ID e o MDM é implantado sozinho.
- O Intune se vende como "sem agentes", mas na prática um **agente é instalado em segundo plano** e fica aguardando instruções do console, como um EDR.

**O que ele faz:** inventário de ativos, envio de políticas, implantação de aplicativos, limpeza de dispositivos, regras de conformidade e integração com o Entra ID. A licença já vem nos planos **Microsoft 365 E3 e E5**.

**Por que importa para o SOC L2**

| Uso | Valor na investigação |
|---|---|
| Inventário de ativos | Contexto sobre o dispositivo investigado |
| Correção/desinstalação de software | Resposta rápida em incidentes de cadeia de suprimentos |
| Políticas e verificações em massa | Instalar agentes de EDR/SIEM em toda a frota |
| Isolamento e reimagem | Reação a roubo ou comprometimento |

### Conformidade e contexto do dispositivo

O Intune marca ativos como **conformes ou não conformes**. Combinado ao **Acesso Condicional**, bloqueia o acesso ao M365 vindo de dispositivos desconhecidos ou fora das regras (ex.: sem BitLocker, sem Defender EDR, senha fraca).

Para o SIEM, os logs de login do Entra ID trazem o campo `deviceDetail`:

| Situação | O que aparece |
|---|---|
| Dispositivo não gerenciado | `deviceDetail` vazio |
| Dispositivo unido ao Entra ID | `trustType` |
| Dispositivo gerenciado pelo Intune | `isCompliant` e `isManaged` |

**9 em cada 10 ataques ao M365 partem de dispositivos não gerenciados.** Se o ataque vem de um dispositivo gerenciado, o mais provável é ameaça interna ou dispositivo infectado/roubado.

---

## 2. Quando o Intune vira arma

| Vetor | O que o invasor faz | Principal rastro |
|---|---|---|
| **Limpeza remota** | Restaura dispositivos para o padrão de fábrica em massa | `wipe ManagedDevice` nos logs de auditoria do Intune |
| **Scripts de plataforma** | Executa PowerShell em massa (usuário ou SYSTEM) | `*DeviceManagementScript*` no SIEM e `AgentExecutor.log` no host |
| **Implantação de apps** | Distribui malware empacotado em `.intunewin` (ou `.dmg`/`.pkg`) com privilégio máximo, mesmo sem assinatura confiável | `*MobileApp*` no SIEM |

### O caso Stryker

Em **11 de março de 2026**, agentes de ameaça supostamente comprometeram uma conta administrativa M365 da Stryker (tecnologia médica, EUA) e emitiram uma limpeza remota em **quase 80.000 dispositivos**. Em poucas horas os dados foram apagados, com grande interrupção das operações.

Ponto-chave: foi **trivial**. Bastaram credenciais válidas de um administrador, possivelmente obtidas por phishing AiTM ou *dumps* de infostealers (não confirmado). A limpeza em massa funciona em todas as plataformas, **exceto Linux**, e o agente redefine o dispositivo assim que recebe o comando.

---

## 3. Como detectar: a linha do tempo do ataque

Não adianta criar uma regra "limpeza em massa via Intune": quando o alerta chegar, a limpeza já terminou, e não há forma documentada de abortar o comando. A estratégia é olhar **o que vem antes e o que fica depois**.

### Etapa 1 — Login no portal

Alertar sobre administradores do Intune entrando por **dispositivos não gerenciados**, **IPs suspeitos** ou **fora do horário de trabalho**. Esses acessos aparecem no Entra ID com `appDisplayName` igual a "Microsoft Intune portal extension".

```spl
index=intune sourcetype=azure:aad:signin appDisplayName=*Intune* deviceDetail.displayName=""
| rename deviceDetail.* as dvc.*
| table _time appDisplayName ipAddress dvc.isManaged dvc.isCompliant dvc.displayName user
```

Um invasor mais avançado pode usar a **Graph API** em vez do navegador; isso é detectável pelo consentimento de aplicativos com permissões OAuth `DeviceManagementManagedDevices.*` ou `DeviceManagementConfiguration.*`.

### Etapa 2 — A ação no Intune

As ações aparecem em **Administrador do locatário > Logs de auditoria do Intune**, em tempo real. Diferente do Entra ID e do M365, esses logs **não vão direto para o SIEM**: é preciso usar a Graph API ou o Azure Event Hub.

**Limpeza:** o evento é `wipe ManagedDevice` e traz o **ID do dispositivo**, não o hostname. Para chegar ao nome da máquina, correlaciono o ID com o evento "Adicionar dispositivo" dos logs de auditoria do Entra ID.

```spl
index=intune sourcetype="o365:graph:intune" wipe
| eval deviceid=mvindex('resources{}.modifiedProperties{}.newValue', 0)
| table _time activityType actor.userPrincipalName deviceid
```

**Scripts:** o ciclo de vida tem quatro estágios (criar, atribuir, executar, excluir). Os três primeiros aparecem na consulta abaixo. O ID `adadadad-808e-44e2-905a-0b7873a8a531` significa **All Devices**.

```spl
index=intune sourcetype="o365:graph:intune" activityType=*DeviceManagementScript*
| eval action=mvindex(split(activityType, " "), 0)
| eval script='resources{}.resourceId'
| eval target=mvindex('resources{}.modifiedProperties{}.newValue', 0)
| eval target=if(action="assignDeviceManagementScript", target, "N/A")
| table _time actor.userPrincipalName action script target
```

**Aplicativos:**

```spl
index=intune sourcetype="o365:graph:intune" activityType=*MobileApp*
```

### Etapa 3 — Rastros no host

No Windows, scripts do Intune seguem sempre a mesma árvore de processos, visível no evento **4688** ou, melhor, no **Sysmon Evento 1**:

```
IntuneWindowsAgent.exe
└── AgentExecutor.exe
    └── powershell.exe -NoProfile -executionPolicy bypass -file "...\Policies\Scripts\<uuid>.ps1"
```

O script é apagado após rodar, mas o `AgentExecutor.log` (em `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`) guarda **hora de execução** (~30 min após a criação no teste), **duração** (eventos de implantação, início e conclusão) e **saída ou erro** em texto simples.

---

## 4. Prática: o que consegui responder

| Pergunta | Resposta | Como cheguei |
|---|---|---|
| ID do dispositivo apagado | `d66b71f3-a644-4392-89b2-d97ba5612356` | Campo `deviceid` na consulta de limpeza |
| Hostname do dispositivo apagado | `LPT-08312` | Correlação do ID com "Adicionar dispositivo" no Entra ID |
| Quando o script foi implantado nos alvos | `2026-03-17 18:57:57` | Linha `assignDeviceManagementScript` na consulta de scripts |
| Saída do script no PC-096 | `THM{hello_world_from_intune!}` | `AgentExecutor.log` do dispositivo |

---

## 5. Como se proteger

O ataque ao Stryker mostrou que **a conta de administrador é o ponto único de falha**. A defesa vem em camadas:

**Proteger as contas privilegiadas**
- Acesso Condicional para bloquear dispositivos e países inesperados
- Proteção de Identidade para alertar ou desativar contas de alto risco
- Logs de login e auditoria do Entra ID para detectar viagens impossíveis e outras anomalias
- **Menos de 5 Administradores Globais**, em qualquer empresa
- Chaves de acesso ou **MFA por hardware** em todas as contas privilegiadas
- **PIM** para tarefas administrativas

**Reduzir o raio de impacto**
- **Funções personalizadas** em vez das padrão. No exemplo do material (30 pessoas entre Segurança, TI global e dois helpdesks), dar "Administrador do Intune" a todos cria 30 contas capazes de limpar em massa. A alternativa são quatro funções: Segurança (limpar), TI global (scripts), Operador de Helpdesk (instalar apps) e Administrador de Helpdesk (apps e políticas).
- **Tags de escopo** para limitar cada função aos ativos que ela precisa gerenciar (no exemplo, UE e EUA).
- **Aprovação de vários administradores** para operações críticas como limpezas e scripts, com apenas um ou dois Administradores Globais podendo editar essas políticas.

---

## Conclusão

Este é o fim da documentação da sala de Microsoft Intune.

O Intune é essencial para centralizar o gerenciamento de dispositivos, mas nas mãos erradas se torna uma ferramenta de ataque tão perigosa quanto um EDR ou RMM comprometido. Nesta sala vi como monitorar o Intune desde o login no portal até os rastros no host, e como reduzir o risco com contas reforçadas, funções personalizadas, tags de escopo e aprovação de vários administradores.

Obrigado por ler e acompanhar esta investigação!
