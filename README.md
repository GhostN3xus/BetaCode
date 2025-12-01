# 🔒 BetaCode - Analisador Estático de Código (SAST)

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**BetaCode** é uma ferramenta profissional de análise estática de código (SAST) que combina as capacidades de Semgrep e Snyk, com relatórios inteligentes em português.

---

## ✨ Features

### 🔍 Detecta Vulnerabilidades
- **SQL Injection** (CWE-89)
- **Cross-Site Scripting (XSS)** (CWE-79)
- **Command Injection** (CWE-78)
- **Path Traversal** (CWE-22)
- **Insecure Deserialization** (CWE-502)
- **XXE (XML External Entity)** (CWE-611)
- **Weak Cryptography** (CWE-327)
- **CSRF** (CWE-352)
- **SSRF** (CWE-918)
- E muito mais...

### 🔑 Detecta Secrets
- AWS Access Keys & Secret Keys
- GitHub Tokens (Personal Access, OAuth, App)
- Stripe Live & Test Keys
- API Keys genéricas
- Passwords hardcoded
- Database Connection Strings
- Private Keys (RSA, DSA, EC)
- JWT Tokens
- Slack Tokens & Webhooks
- Discord Tokens
- E mais 15+ tipos...

### 📦 Análise de Dependências
- Detecta CVEs em dependências
- Suporta Python, JavaScript, Java, Go, Ruby, PHP

### 📊 Análise de Qualidade
- TODOs e FIXMEs
- Funções muito longas
- Linhas muito longas
- Código comentado

---

## 🚀 Instalação

### Requisitos
- Python 3.11+

### Via pip (desenvolvimento)
```bash
git clone https://github.com/GhostN3xus/BetaCode.git
cd BetaCode
pip install -e .
```

---

## 📖 Uso Rápido

### CLI Básico
```bash
# Analisar um arquivo
betacode analyze /caminho/para/arquivo.py

# Analisar um diretório
betacode analyze /caminho/para/projeto

# Especificar formato de output
betacode analyze /caminho --format json --format html
```

### Uso Programático (Python)
```python
from betacode.core.engine import BetaCodeEngine

# Criar engine
engine = BetaCodeEngine()

# Executar análise
result = engine.analyze("/caminho/para/codigo")

# Verificar findings
print(f"Total: {result.total_findings}")
print(f"Risk Score: {result.metrics['risk_score']}/100")
```

---

## ⚙️ Configuração

### Arquivo de Configuração (YAML)
Crie `betacode.yaml`:

```yaml
languages:
  - python
  - javascript
workers: 4
severity_level: MEDIUM
output_formats:
  - json
  - html
```

---

## 🎯 Linguagens Suportadas

✅ Python | ✅ JavaScript/TypeScript | ✅ Java | ✅ C/C++ | ✅ C# | ✅ Go | ✅ Rust | ✅ Ruby | ✅ PHP | ✅ Swift | ✅ Kotlin

---

## 📜 Licença

MIT License - veja LICENSE para detalhes.

---

**Made with ❤️ by BetaCode Team**
