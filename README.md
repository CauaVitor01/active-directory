# Active Directory: Hardening & Detection

![Active Directory](https://img.shields.io/badge/Active_Directory-0078D6?style=flat-square&logo=microsoft&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red?style=flat-square)
![Splunk](https://img.shields.io/badge/Splunk-000000?style=flat-square&logo=splunk&logoColor=white)

**🇬🇧 [English](#-english) &nbsp;|&nbsp; 🇧🇷 [Português](#-português)**

---

## 🇬🇧 English

Documentation on securing and monitoring Windows **Active Directory** environments — hardening strategy on one side, initial-access detection on the other.

### ✅ Completed

| Project | What it covers |
|---|---|
| [**AD Hardening & Infrastructure Security**](./AD-Hardening-and-Security/active_directory_hardening.md) | Hardening framework covering least-privilege (PoLP), Tiered Administration (Tier 0/1/2), legacy hash disablement, SMB/LDAP signing, gMSAs, Kerberoasting mitigation, and baseline auditing with the Microsoft Security Compliance Toolkit. Mapped to MITRE ATT&CK (T1550 Pass-the-Hash, T1558 Kerberoasting) |
| [**Initial Access Detection in AD Environments**](./AD-Hardening-and-Security/initial-access-detection-report.md) | Detection methodology for initial-access attacks against IIS web apps, Exchange OWA, and VPN gateways — correlating application logs (IIS, NPS) with Windows Security events (4624, 4625, 4776) and Sysmon in Splunk to reconstruct attack timelines |

### 🗺️ Roadmap (planned, not yet executed)

The following are *planned* hands-on lab exercises — listed here to show direction, not as completed work:
- Full attack-path lab: Kerberoasting, AS-REP Roasting, DCSync, Golden Ticket creation
- Attack-path mapping with BloodHound + remediation of identified trust relationships
- End-to-end Red Team simulation validated against SOC detection (adversary simulation playbooks)

### Skills demonstrated (completed work)
Active Directory security architecture · Tiered Administration Model · GPO hardening · SIEM-based initial-access detection (Splunk) · MITRE ATT&CK mapping

---

## 🇧🇷 Português

Documentação sobre proteção e monitoramento de ambientes **Active Directory** no Windows — estratégia de hardening de um lado, detecção de acesso inicial do outro.

### ✅ Concluído

| Projeto | O que cobre |
|---|---|
| [**Hardening e Segurança de Infraestrutura do AD**](./AD-Hardening-and-Security/active_directory_hardening.md) | Framework de hardening cobrindo privilégio mínimo (PoLP), Modelo de Administração em Camadas (Tier 0/1/2), desativação de hashes legados, SMB/LDAP signing, gMSAs, mitigação de Kerberoasting e auditoria de baseline com o Microsoft Security Compliance Toolkit. Mapeado ao MITRE ATT&CK (T1550 Pass-the-Hash, T1558 Kerberoasting) |
| [**Detecção de Acesso Inicial em Ambientes AD**](./AD-Hardening-and-Security/initial-access-detection-report.md) | Metodologia de detecção para ataques de acesso inicial contra aplicações web IIS, Exchange OWA e gateways VPN — correlacionando logs de aplicação (IIS, NPS) com eventos de Segurança do Windows (4624, 4625, 4776) e Sysmon no Splunk para reconstruir linhas do tempo de ataque |

### 🗺️ Roadmap (planejado, ainda não executado)

Os itens abaixo são laboratórios práticos *planejados* — listados aqui para mostrar direção, não como trabalho concluído:
- Laboratório completo de attack-path: Kerberoasting, AS-REP Roasting, DCSync, criação de Golden Ticket
- Mapeamento de caminhos de ataque com BloodHound + remediação das relações de confiança identificadas
- Simulação Red Team completa validada contra detecção do SOC (playbooks de simulação de adversário)

### Habilidades demonstradas (trabalho concluído)
Arquitetura de segurança de Active Directory · Modelo de Administração em Camadas · Hardening via GPO · Detecção de acesso inicial baseada em SIEM (Splunk) · Mapeamento MITRE ATT&CK
