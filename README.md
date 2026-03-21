# Active Directory Security & Attack

Este repositório documenta estudos práticos e implementações focadas na segurança do **Active Directory**, com ênfase em **hardening, monitoramento e detecção de atividades maliciosas** em ambientes corporativos Windows.

O objetivo é demonstrar técnicas utilizadas por equipes de **Blue Team e SOC** para proteger infraestruturas baseadas em domínio, identificar comportamentos suspeitos e responder a possíveis compromissos do ambiente.

---

## Objetivos do Projeto

* **Arquitetura e Protocolos:** Analisar o funcionamento interno dos protocolos Kerberos, NTLM e LDAP, identificando fraquezas em configurações legadas e vetores de exploração.

* **Hardening e Redução de Superfície:** Implementar o *Tiered Administration Model* (Tier 0, 1 e 2) para isolar ativos críticos e impedir a escalação de privilégios entre camadas.

* **Gestão de Identidade Privilegiada:** Aplicar o Princípio do Privilégio Mínimo (PoLP) e configurar gMSAs (*Group Managed Service Accounts*) para eliminar senhas estáticas em serviços.

* **Controle de Movimentação Lateral:** Configurar GPOs de restrição, desabilitar protocolos inseguros (LLMNR/NetBIOS) e implementar o LAPS para gerenciar senhas de administradores locais.

* **Monitoramento e Auditoria Avançada:** Definir políticas de auditoria detalhadas e utilizar o **Sysmon** para capturar telemetria crítica que o log padrão do Windows costuma omitir.

* **Detecção de Ameaças (Threat Hunting):** Desenvolver consultas e alertas para identificar ataques clássicos como *Kerberoasting*, *AS-REP Roasting*, *DCSync* e *Golden Ticket*.

* **Análise de Vulnerabilidades:** Utilizar ferramentas de auditoria (como PingCastle ou BloodHound) para mapear caminhos de ataque ocultos e pontos cegos na estrutura do domínio.

* **Resposta a Incidentes:** Elaborar playbooks práticos para isolamento de contas comprometidas, limpeza de persistência e remediação de vetores explorados.

