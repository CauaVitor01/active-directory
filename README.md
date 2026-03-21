## Active Directory: Attack & Defense Lab

Este repositório documenta estudos práticos e implementações focadas na segurança do **Active Directory**, explorando o ciclo completo de um ataque: desde a enumeração e exploração até o **hardening, monitoramento e detecção** em ambientes corporativos Windows.

O objetivo é demonstrar a mentalidade de um atacante para construir defesas robustas, auxiliando equipes de **Red Team, Blue Team e SOC** a identificar vulnerabilidades e responder a incidentes no domínio.

---

## Objetivos do Projeto

* **Exploração de Protocolos:** Simular ataques aos protocolos Kerberos, NTLM e LDAP para entender como fraquezas em configurações legadas podem ser exploradas.
* **Elevação de Privilégios e Persistência:** Demonstrar técnicas como *Kerberoasting*, *AS-REP Roasting*, *DCSync* e a criação de *Golden Tickets* para validar a eficácia dos controles de segurança.
* **Mapeamento de Caminhos de Ataque:** Utilizar ferramentas como BloodHound para identificar relações de confiança e caminhos críticos, seguido da remediação desses vetores.
* **Hardening e Redução de Superfície:** Implementar o *Tiered Administration Model* (Tier 0, 1 e 2) e o LAPS para mitigar a movimentação lateral e o roubo de credenciais.
* **Gestão de Identidade e Privilégios:** Aplicar o Princípio do Privilégio Mínimo (PoLP) e gMSAs para reduzir a superfície de ataque em contas de serviço e administrativas.
* **Monitoramento e Threat Hunting:** Configurar auditoria avançada e **Sysmon** para gerar telemetria capaz de detectar indicadores de ataque (IoAs) e comportamento anômalo.
* **Simulação de Adversários:** Executar playbooks de ataque controlados para testar a capacidade de detecção do SOC e a resiliência das políticas de GPO.
* **Resposta a Incidentes e Remediação:** Desenvolver guias práticos para isolar contas comprometidas, remover persistência e aplicar correções definitivas após um compromisso.

---
