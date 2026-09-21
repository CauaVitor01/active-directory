# Active Directory — Lateral Movement Detection & Investigation

Investigação de técnicas de movimentação lateral em ambientes Active Directory utilizando Splunk, Windows Security Logs e Sysmon.

## 🎯 Objetivo

Investigar e detectar movimentação lateral utilizando protocolos e ferramentas legítimas do ambiente Windows, correlacionando eventos de diferentes máquinas para reconstruir a cadeia de ataque.

A investigação abordou:

- Active Directory Discovery
- SMB
- PsExec
- RDP
- Windows Security Events
- Sysmon
- PowerShell Script Block Logging
- Correlação de eventos
- Backtracking da origem do ataque

---

# 🔎 1. Active Directory Discovery

Antes de realizar movimentação lateral, um atacante precisa descobrir informações sobre o ambiente.

Foram analisados comandos utilizados para identificar:

- Controladores de domínio
- Contas de usuários
- Grupos privilegiados
- Relações de confiança
- Computadores do domínio
- Sistemas disponíveis na rede

### Comandos analisados

```text
nltest /dclist:<dominio>
nltest /domain_trusts
net user /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net view
net view \\<host> /all
Get-ADUser -Filter *
Get-ADGroupMember "Domain Admins"
Get-ADComputer -Filter *
Detecção com Sysmon

O Sysmon Event ID 1 foi utilizado para identificar processos e linhas de comando relacionadas à descoberta.

index=win EventCode=1
| search CommandLine IN (
    "*nltest*",
    "*net * user*",
    "*net * group*",
    "*net * view*",
    "*net * localgroup*"
)
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
Detecção com PowerShell

O PowerShell Script Block Logging foi utilizado para identificar cmdlets de descoberta.

index=win EventCode=4104
| search Message IN (
    "*Get-ADUser*",
    "*Get-ADGroupMember*",
    "*Get-ADComputer*"
)
| table _time, Message
| sort _time

Resultado

O primeiro comando de descoberta identificado foi:

nltest /domain_trusts
🔗 2. Investigação de Movimentação Lateral

A investigação foi baseada no modelo:

ORIGEM → AUTENTICAÇÃO → DESTINO → EXECUÇÃO

Uma conexão remota pode gerar artefatos diferentes na máquina de origem e na máquina de destino.

Por isso, a investigação não foi limitada a um único host.

Windows Logon Types
Logon Type	Significado	Contexto
3	Network Logon	SMB / PsExec
7	Unlock / Reconnect	Reconexão
10	Remote Interactive	RDP

O Event ID 4624 foi utilizado para identificar as sessões de autenticação.

🗂️ 3. Movimentação Lateral via SMB

O SMB pode ser utilizado para acessar compartilhamentos administrativos do Windows.

Foram analisados principalmente:

C$
ADMIN$
IPC$
Eventos utilizados
Event ID 5140 — acesso a compartilhamento de rede
Event ID 4624 — autenticação
Event ID 4648 — uso de credenciais explícitas
Sysmon Event ID 1 — criação de processos
Detecção de ADMIN$
index=win EventCode=5140
Share_Name IN ("*\\ADMIN$\*", "*\\C$\*")
| table _time, host, Source_Address, user, Share_Name
| sort _time

A investigação buscou identificar:

IP de origem
      ↓
Host de origem
      ↓
Conta utilizada
      ↓
Compartilhamento acessado
      ↓
Host de destino
Linha de base

A atividade observada foi comparada ao comportamento histórico da conta.

index=win EventCode=5140 user={USER_ACCOUNT}
| table _time, Source_Address, Share_Name, host
| sort _time

Resultado

A conta utilizada para acessar os compartilhamentos ADMIN$ foi:

luke.sullivan
⚙️ 4. Movimentação Lateral via PsExec

O PsExec combina acesso SMB com instalação de um serviço no computador remoto para executar comandos.

Fluxo observado:

SMB
 ↓
ADMIN$
 ↓
PSEXESVC.exe
 ↓
Windows Service
 ↓
Execução remota
Artefatos utilizados
Event ID 7045

Identificação de novos serviços:

index=win EventCode=7045
| table _time, host, Service_Name,
        Service_File_Name,
        Service_Type,
        Service_Start_Type,
        Service_Account
| sort _time
Sysmon Event ID 1

Identificação dos processos executados pelo serviço:

index=win EventCode=1
host={DESTINATION_HOST}
ParentImage="*PSEXESVC*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
Sysmon Event ID 17

Identificação dos named pipes:

index=win EventCode=17
Image="*PSEXESVC*"
| table _time, host, Image, PipeName
| sort _time
Event ID 5145

Análise detalhada do acesso ao compartilhamento:

index=win EventCode=5145
host={DESTINATION_HOST}
Relative_Target_Name="*PSEXE*"
| table _time, user, Source_Address,
        Share_Name, Relative_Target_Name
| sort _time
Investigação da origem
index=win EventCode=1
host={SOURCE_HOST}
| search Image="*PsExec*"
| table _time, host, User, Image, CommandLine
| sort _time
Resultado

Host de destino:

THM-SQL-SRV

Primeiro comando executado:

C:\Tools\PsExec.exe -accepteula \\THM-SQL-SRV cmd /c "hostname & whoami & ipconfig"

🖥️ 5. Movimentação Lateral via RDP

O RDP foi investigado principalmente através do:

Event ID 4624
Logon Type 10

Também foram considerados:

Event ID 4624
Sysmon Event ID 1
mstsc.exe
LogonId
Source_Network_Address
Metodologia de Investigação

A investigação iniciou no Controlador de Domínio após a identificação de comandos de descoberta.

Passo 1 — Identificar a sessão
index=win EventCode=4624
host=THM-DC
Logon_ID={LOGON_ID}
| table _time, user, Logon_Type,
        Source_Network_Address, Logon_ID
Passo 2 — Identificar o host intermediário

O endereço IP de origem foi utilizado para identificar o servidor intermediário.

Passo 3 — Identificar RDP de saída
index=win EventCode=1
host={SOURCE_SERVER}
Image="*mstsc.exe*"
| table _time, User, Image, CommandLine, LogonId
| sort _time
Passo 4 — Rastrear a origem

O LogonId foi correlacionado novamente com os eventos de autenticação para reconstruir os saltos realizados pelo atacante.

Estação comprometida
        ↓
Servidor intermediário
        ↓
Controlador de Domínio

🚨 6. Desafio Prático — Backtracking
Cenário

O SOC recebeu um alerta crítico de EDR relacionado à instalação de um serviço anômalo:

Service: svcupdate
Host: THM-SHR-SRV

Não havia implantação de software homologada ou mudança planejada para o período.

A investigação foi realizada no Splunk utilizando:

index=challenge
Metodologia

A investigação foi realizada de trás para frente:

Serviço malicioso
      ↓
Acesso ADMIN$
      ↓
Conta utilizada
      ↓
IP de origem
      ↓
Hostname de origem
      ↓
Comando executado
1. Identificação do serviço

Event ID:

7045

Objetivo:

Identificar o serviço svcupdate e seu caminho de execução.

2. Rastreamento do acesso SMB

Event ID:

5140

Objetivo:

Identificar a conta utilizada para acessar ADMIN$.

3. Identificação do host de origem

Event ID:

4624

Objetivo:

Relacionar o endereço IP ao hostname de origem.

4. Identificação da execução

Sysmon Event ID:

1

Objetivo:

Identificar o comando executado na máquina de origem.

🔍 Resultados da Investigação
Evidência	Resultado
Serviço instalado	%SystemRoot%\svcupdate.exe
Conta utilizada	ryan.chen
IP de origem	10.5.50.15
Primeiro comando remoto	cmd /c "hostname & whoami & ipconfig"
Host de origem	THM-HR-WS
Cadeia reconstruída
THM-HR-WS
    │
    │ SMB / ADMIN$
    ▼
THM-SHR-SRV
    │
    │ Serviço svcupdate
    ▼
Execução remota

🧠 Principais Técnicas Investigadas
Técnica / Artefato	Evidência
AD Discovery	Sysmon Event 1 / PowerShell 4104
SMB	Event 5140 / 4624 / 4648
PsExec	Event 7045 / Sysmon 1 / 17 / Event 5145
RDP	Event 4624 / Logon Type 10 / Sysmon 1
RDP Chaining	Correlação de LogonId
Credential Abuse	4624 / 4648 / CommandLine
Backtracking	Correlação origem → destino
SIEM Investigation	Splunk
🛡️ MITRE ATT&CK

Técnicas relacionadas à investigação:

T1018 — Remote System Discovery
T1087 — Account Discovery
T1069 — Permission Groups Discovery
T1135 — Network Share Discovery
T1021.001 — Remote Services: RDP
T1021.002 — Remote Services: SMB/Windows Admin Shares
T1569.002 — System Services: Service Execution
📌 Conclusão

A investigação demonstrou como diferentes fontes de telemetria podem ser correlacionadas para reconstruir uma movimentação lateral dentro de um ambiente Active Directory.

A análise combinou:

Windows Security Logs
        +
Sysmon
        +
PowerShell Logs
        +
Splunk
        +
Contexto do ambiente

O resultado foi a reconstrução do caminho do atacante desde o host de origem até o servidor comprometido.

🧰 Tecnologias
Splunk
Windows Server
Active Directory
Sysmon
PowerShell
Windows Security Event Logs
SMB
RDP
PsExec
MITRE ATT&CK
🎓 Competências Demonstradas
SOC Investigation
Threat Detection
Active Directory Monitoring
Windows Event Analysis
SIEM Investigation
Log Correlation
Lateral Movement Detection
Attack Path Reconstruction
Incident Investigation
