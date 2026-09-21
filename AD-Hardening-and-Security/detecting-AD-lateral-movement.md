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

## 🔎 1. Active Directory Discovery

Antes de realizar movimentação lateral, um atacante precisa descobrir informações sobre o ambiente. Foram analisados comandos utilizados para identificar:

- Controladores de domínio
- Contas de usuários
- Grupos privilegiados
- Relações de confiança
- Computadores do domínio
- Sistemas disponíveis na rede

### Comandos analisados

```bash
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
Detecção com SysmonO Sysmon Event ID 1 foi utilizado para identificar processos e linhas de comando relacionadas à descoberta.Splunk SPLindex=win EventCode=1
| search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*", "*net * localgroup*")
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
Detecção com PowerShellO PowerShell Script Block Logging foi utilizado para identificar cmdlets de descoberta.Splunk SPLindex=win EventCode=4104
| search Message IN ("*Get-ADUser*", "*Get-ADGroupMember*", "*Get-ADComputer*")
| table _time, Message
| sort _time
Evidência:[Insira Imagem]Resultado:O primeiro comando de descoberta identificado foi:nltest /domain_trusts🔗 2. Investigação de Movimentação LateralA investigação foi baseada no modelo:ORIGEM → AUTENTICAÇÃO → DESTINO → EXECUÇÃOUma conexão remota pode gerar artefatos diferentes na máquina de origem e na máquina de destino. Por isso, a investigação não foi limitada a um único host.Windows Logon TypesO Event ID 4624 foi utilizado para identificar as sessões de autenticação.Logon TypeSignificadoContexto3Network LogonSMB / PsExec7Unlock / ReconnectReconexão10Remote InteractiveRDP🗂️ 3. Movimentação Lateral via SMBO SMB pode ser utilizado para acessar compartilhamentos administrativos do Windows. Foram analisados principalmente: C$, ADMIN$, IPC$.Eventos utilizados:Event ID 5140 — acesso a compartilhamento de redeEvent ID 4624 — autenticaçãoEvent ID 4648 — uso de credenciais explícitasSysmon Event ID 1 — criação de processosDetecção de ADMIN$Splunk SPLindex=win EventCode=5140 Share_Name IN ("*\\ADMIN$\*", "*\\C$\*")
| table _time, host, Source_Address, user, Share_Name
| sort _time
A investigação buscou identificar o fluxo:IP de origem ➔ Host de origem ➔ Conta utilizada ➔ Compartilhamento acessado ➔ Host de destinoLinha de baseA atividade observada foi comparada ao comportamento histórico da conta.Splunk SPLindex=win EventCode=5140 user={USER_ACCOUNT}
| table _time, Source_Address, Share_Name, host
| sort _time
Evidência:[Insira Imagem]Resultado:A conta utilizada para acessar os compartilhamentos ADMIN$ foi: luke.sullivan⚙️ 4. Movimentação Lateral via PsExecO PsExec combina acesso SMB com instalação de um serviço no computador remoto para executar comandos.Fluxo observado:SMB ➔ ADMIN$ ➔ PSEXESVC.exe ➔ Windows Service ➔ Execução remotaArtefatos utilizadosEvent ID 7045 (Identificação de novos serviços):Splunk SPLindex=win EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
| sort _time
Sysmon Event ID 1 (Identificação dos processos executados pelo serviço):Splunk SPLindex=win EventCode=1 host={DESTINATION_HOST} ParentImage="*PSEXESVC*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
Sysmon Event ID 17 (Identificação dos named pipes):Splunk SPLindex=win EventCode=17 Image="*PSEXESVC*"
| table _time, host, Image, PipeName
| sort _time
Event ID 5145 (Análise detalhada do acesso ao compartilhamento):Splunk SPLindex=win EventCode=5145 host={DESTINATION_HOST} Relative_Target_Name="*PSEXE*"
| table _time, user, Source_Address, Share_Name, Relative_Target_Name
| sort _time
Investigação da origem:Splunk SPLindex=win EventCode=1 host={SOURCE_HOST}
| search Image="*PsExec*"
| table _time, host, User, Image, CommandLine
| sort _time
Resultados:Host de destino: THM-SQL-SRVPrimeiro comando executado: C:\Tools\PsExec.exe -accepteula \\THM-SQL-SRV cmd /c "hostname & whoami & ipconfig"Evidência:[Insira Imagem]🖥️ 5. Movimentação Lateral via RDPO RDP foi investigado principalmente através do Event ID 4624 (Logon Type 10). Também foram considerados Sysmon Event ID 1, mstsc.exe, LogonId e Source_Network_Address.Metodologia de InvestigaçãoA investigação iniciou no Controlador de Domínio após a identificação de comandos de descoberta.Passo 1 — Identificar a sessão:Splunk SPLindex=win EventCode=4624 host=THM-DC Logon_ID={LOGON_ID}
| table _time, user, Logon_Type, Source_Network_Address, Logon_ID
Passo 2 — Identificar o host intermediário:O endereço IP de origem foi utilizado para identificar o servidor intermediário.Passo 3 — Identificar RDP de saída:Splunk SPLindex=win EventCode=1 host={SOURCE_SERVER} Image="*mstsc.exe*"
| table _time, User, Image, CommandLine, LogonId
| sort _time
Passo 4 — Rastrear a origem:O LogonId foi correlacionado novamente com os eventos de autenticação para reconstruir os saltos realizados pelo atacante (RDP Chaining).Estação comprometida ➔ Servidor intermediário ➔ Controlador de DomínioEvidência:[Insira Imagem]🚨 6. Desafio Prático — BacktrackingCenárioO SOC recebeu um alerta crítico de EDR relacionado à instalação de um serviço anômalo:Service: svcupdateHost: THM-SHR-SRVNão havia implantação de software homologada ou mudança planejada para o período. A investigação foi realizada no Splunk utilizando index=challenge.MetodologiaA investigação foi realizada de trás para frente (Backtracking):Serviço malicioso ➔ Acesso ADMIN$ ➔ Conta utilizada ➔ IP de origem ➔ Hostname de origem ➔ Comando executadoIdentificação do serviço (Event ID 7045): Identificar o serviço svcupdate e seu caminho de execução.Rastreamento do acesso SMB (Event ID 5140): Identificar a conta utilizada para acessar ADMIN$.Identificação do host de origem (Event ID 4624): Relacionar o endereço IP ao hostname de origem.Identificação da execução (Sysmon Event ID 1): Identificar o comando executado na máquina de origem.🔍 Resultados da InvestigaçãoEvidênciaResultadoServiço instalado%SystemRoot%\svcupdate.exeConta utilizadaryan.chenIP de origem10.5.50.15Primeiro comando remotocmd /c "hostname & whoami & ipconfig"Host de origemTHM-HR-WSCadeia reconstruída:PlaintextTHM-HR-WS
    │
    │ SMB / ADMIN$
    ▼
THM-SHR-SRV
    │
    │ Serviço svcupdate
    ▼
Execução remota
Evidência:[Insira Imagem]🧠 Principais Técnicas InvestigadasTécnica / ArtefatoEvidênciaAD DiscoverySysmon Event 1 / PowerShell 4104SMBEvent 5140 / 4624 / 4648PsExecEvent 7045 / Sysmon 1 / 17 / Event 5145RDPEvent 4624 / Logon Type 10 / Sysmon 1RDP ChainingCorrelação de LogonIdCredential Abuse4624 / 4648 / CommandLineBacktrackingCorrelação origem ➔ destinoSIEM InvestigationSplunk🛡️ MITRE ATT&CKTécnicas relacionadas à investigação:T1018 — Remote System DiscoveryT1087 — Account DiscoveryT1069 — Permission Groups DiscoveryT1135 — Network Share DiscoveryT1021.001 — Remote Services: RDPT1021.002 — Remote Services: SMB/Windows Admin SharesT1569.002 — System Services: Service Execution📌 ConclusãoA investigação demonstrou como diferentes fontes de telemetria podem ser correlacionadas para reconstruir uma movimentação lateral dentro de um ambiente Active Directory. A análise combinou o contexto do ambiente com os logs do Windows Security, Sysmon e PowerShell através do Splunk. O resultado foi a reconstrução completa do caminho do atacante, desde o host de origem até o servidor comprometido, evidenciando a eficácia do rastreamento de saltos intermediários e do abuso de ferramentas nativas.🧰 Tecnologias & 🎓 Competências DemonstradasTecnologias: Splunk, Windows Server, Active Directory, Sysmon, PowerShell, Windows Security Event Logs, SMB, RDP, PsExec, MITRE ATT&CK.Competências: SOC Investigation, Threat Detection, Active Directory Monitoring, Windows Event Analysis, SIEM Investigation, Log Correlation, Lateral Movement Detection, Attack Path Reconstruction, Incident Investigation.
