# Active Directory Hardening & Infrastructure Security

Este repositório apresenta uma documentação estratégica e técnica sobre o fortalecimento de infraestruturas **Active Directory (AD)**. O foco deste projeto é a implementação do modelo de privilégio mínimo, segregação de redes e mitigação de vetores de ataque críticos para garantir a resiliência do ambiente corporativo.

> 📂 **[ACESSAR DOCUMENTAÇÃO COMPLETA (PDF)](./active_directory_hardening.pdf)**

---

## Conteúdo do Projeto

Este guia de hardening detalha as camadas de defesa necessárias para proteger identidades e recursos em uma rede Windows:

### 1. Governança de Identidade (IAM)
* **Princípio do Privilégio Mínimo (PoLP):** Implementação de contas de usuário padrão vs. privilegiadas.
* **Modelo de Acesso em Camadas (Tiering):** Estruturação da rede em Tier 0 (Crítico/DC), Tier 1 (Servidores) e Tier 2 (Workstations) para impedir a movimentação lateral.

### 2. Endurecimento de Sistemas (Hardening via GPO)
* **Segurança de Credenciais:** Desativação de hashes legados (LM Hash) e aplicação de políticas de senhas robustas.
* **Proteção de Tráfego:** Implementação de **SMB Signing** e **LDAP Signing** para mitigar ataques de Man-in-the-Middle (MiTM) e Relay.
* **Gestão Automatizada:** Uso de Contas de Serviço Gerenciadas em Grupo (**gMSAs**) para rotação automática de senhas.

### 3. Análise de Vulnerabilidades e Defesa
* **Mitigação de Kerberoasting:** Estratégias de proteção contra o abuso de tickets TGS e SPNs mal configurados.
* **Auditoria de Conformidade:** Utilização do **Microsoft Security Compliance Toolkit (MSCT)** e **Policy Analyzer** para validar baselines de segurança.
* **Monitoramento Forense:** Identificação de Event IDs críticos (4728, 4732) para detecção de alterações em grupos sensíveis.

---

## Tecnologias e Ferramentas Aplicadas

* **Microsoft Active Directory:** Gestão de domínios, florestas e relações de confiança (Trusts).
* **GPO (Group Policy Objects):** Distribuição de políticas de segurança em larga escala.
* **PowerShell:** Auditoria de compartilhamentos de rede (SMB) e execução de baselines de segurança.
* **MITRE ATT&CK:** Mapeamento de técnicas como T1550 (Pass-the-Hash) e T1558 (Kerberoasting).

---

## Analista Responsável

* **Nome:** Cauã
* **Especialidade:** Blue Team / Security Analyst
* **Data do Relatório:** 14 de Março de 2026

---

### 📂 Como utilizar este repositório
1. Consulte o [PDF Principal](./active_directory_hardening.pdf) para uma visão técnica profunda.
2. Utilize as seções de GPO como guia para auditorias em ambientes de teste (Lab).
3. Siga o modelo de camadas para reestruturar permissões de acesso em infraestruturas legadas.
