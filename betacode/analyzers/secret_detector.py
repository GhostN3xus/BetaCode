"""
BetaCode - Secret Detector

Este módulo detecta credenciais, API keys, tokens e outros secrets
hardcoded no código-fonte.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

import re
from typing import List, Dict, Tuple
from ..core.base_types import Finding, Severity, FindingType, FindingStatus
from ..utils.logger import get_logger

logger = get_logger(__name__)


class SecretDetector:
    """
    Detecta secrets e credenciais hardcoded no código.

    Detecta:
    - AWS Access Keys
    - GitHub Tokens
    - Stripe Keys
    - API Keys genéricas
    - Passwords hardcoded
    - Database credentials
    - Private keys
    - JWT tokens
    - Slack tokens
    - Discord tokens
    - Twilio credentials
    - E mais...
    """

    # Patterns para detecção de secrets
    PATTERNS: Dict[str, Dict[str, any]] = {
        'aws_access_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'name': 'AWS Access Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'aws_secret_key': {
            'pattern': r'(?i)aws[_-]?secret[_-]?access[_-]?key[\'"\s:=]+([a-zA-Z0-9/+=]{40})',
            'name': 'AWS Secret Access Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'github_token': {
            'pattern': r'ghp_[0-9a-zA-Z]{36}',
            'name': 'GitHub Personal Access Token',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'github_oauth': {
            'pattern': r'gho_[0-9a-zA-Z]{36}',
            'name': 'GitHub OAuth Token',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'github_app_token': {
            'pattern': r'(ghu|ghs)_[0-9a-zA-Z]{36}',
            'name': 'GitHub App Token',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'stripe_live_key': {
            'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
            'name': 'Stripe Live API Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'stripe_test_key': {
            'pattern': r'sk_test_[0-9a-zA-Z]{24,}',
            'name': 'Stripe Test API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
        'api_key_generic': {
            'pattern': r'(?i)(api[_-]?key|apikey)[\'"\s:=]+[\'"]([a-zA-Z0-9_\-]{20,})[\'"]',
            'name': 'Generic API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
        'password_hardcoded': {
            'pattern': r'(?i)(password|passwd|pwd)[\'"\s:=]+[\'"]([^\'"]{8,})[\'"]',
            'name': 'Hardcoded Password',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'db_connection_string': {
            'pattern': r'(?i)(mysql|postgres|mongodb|redis)://[^:]+:([^@]+)@',
            'name': 'Database Connection String with Password',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'private_key_rsa': {
            'pattern': r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'name': 'Private Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            'name': 'JWT Token',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'name': 'Slack Token',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'slack_webhook': {
            'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            'name': 'Slack Webhook URL',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
        'discord_token': {
            'pattern': r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}',
            'name': 'Discord Token',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
        'twilio_api_key': {
            'pattern': r'SK[0-9a-fA-F]{32}',
            'name': 'Twilio API Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'google_api_key': {
            'pattern': r'AIza[0-9A-Za-z_-]{35}',
            'name': 'Google API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
        'facebook_access_token': {
            'pattern': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'name': 'Facebook Access Token',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
        'azure_storage_key': {
            'pattern': r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([^;]+);',
            'name': 'Azure Storage Account Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-798',
        },
        'heroku_api_key': {
            'pattern': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'name': 'Heroku API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
        'mailgun_api_key': {
            'pattern': r'key-[0-9a-zA-Z]{32}',
            'name': 'Mailgun API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
        'sendgrid_api_key': {
            'pattern': r'SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}',
            'name': 'SendGrid API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-798',
        },
    }

    # Padrões de falso positivo (para reduzir ruído)
    FALSE_POSITIVE_PATTERNS = [
        r'example',
        r'sample',
        r'test',
        r'fake',
        r'dummy',
        r'placeholder',
        r'<.*>',
        r'\{.*\}',
        r'\$\{.*\}',
        r'YOUR_.*',
        r'REPLACE_.*',
    ]

    def __init__(self):
        """Inicializa o detector de secrets"""
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.compiled_fp_patterns: List[re.Pattern] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pré-compila todos os patterns regex para performance"""
        for secret_type, config in self.PATTERNS.items():
            try:
                self.compiled_patterns[secret_type] = re.compile(config['pattern'])
            except re.error as e:
                logger.error(f"Erro ao compilar pattern {secret_type}: {e}")

        # Compilar patterns de falso positivo
        for fp_pattern in self.FALSE_POSITIVE_PATTERNS:
            try:
                self.compiled_fp_patterns.append(re.compile(fp_pattern, re.IGNORECASE))
            except re.error as e:
                logger.error(f"Erro ao compilar FP pattern: {e}")

    def detect(self, code: str, file_path: str) -> List[Finding]:
        """
        Detecta secrets no código-fonte.

        Args:
            code: Código-fonte para analisar
            file_path: Caminho do arquivo

        Returns:
            Lista de findings de secrets detectados
        """
        findings = []

        for secret_type, config in self.PATTERNS.items():
            pattern = self.compiled_patterns.get(secret_type)
            if not pattern:
                continue

            matches = pattern.finditer(code)

            for match in matches:
                # Verificar falso positivo
                if self._is_false_positive(match.group(0)):
                    logger.debug(f"Falso positivo ignorado: {secret_type} em {file_path}")
                    continue

                # Calcular linha e coluna
                line_num = code[:match.start()].count('\n') + 1
                line_start = code[:match.start()].rfind('\n') + 1
                col_num = match.start() - line_start + 1

                # Extrair snippet
                code_lines = code.split('\n')
                snippet = code_lines[line_num - 1] if line_num <= len(code_lines) else ""

                # Truncar valor do secret para não expor
                secret_value = match.group(0)
                if len(secret_value) > 10:
                    masked_value = secret_value[:10] + "***"
                else:
                    masked_value = "***"

                # Criar finding
                finding = Finding(
                    id=Finding.generate_id(file_path, line_num, f"secret_{secret_type}"),
                    rule_id=f"secret_{secret_type}",
                    finding_type=FindingType.SECRET,
                    severity=Severity[config['severity']],
                    file=file_path,
                    line=line_num,
                    column=col_num,
                    message=f"🔑 Credencial detectada: {config['name']}",
                    code_snippet=snippet.strip(),
                    cwe=config['cwe'],
                    owasp="A07:2021 - Identification and Authentication Failures",
                    remediations=self._get_remediation_steps(secret_type, config['name']),
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                        "https://cwe.mitre.org/data/definitions/798.html",
                    ],
                    context={
                        'secret_type': secret_type,
                        'masked_value': masked_value
                    }
                )

                findings.append(finding)
                logger.info(
                    f"Secret detectado: {config['name']} em {file_path}:{line_num}"
                )

        return findings

    def _is_false_positive(self, match_text: str) -> bool:
        """
        Verifica se um match é um falso positivo.

        Args:
            match_text: Texto do match

        Returns:
            True se é falso positivo
        """
        for fp_pattern in self.compiled_fp_patterns:
            if fp_pattern.search(match_text):
                return True
        return False

    def _get_remediation_steps(self, secret_type: str, secret_name: str) -> List[str]:
        """
        Retorna passos de remediação específicos para o tipo de secret.

        Args:
            secret_type: Tipo do secret
            secret_name: Nome do secret

        Returns:
            Lista de passos de remediação
        """
        common_steps = [
            f"1. ⚠️  **AÇÃO IMEDIATA**: Revogue a credencial {secret_name} imediatamente",
            "2. 🔄 Gere uma nova credencial no serviço correspondente",
            "3. 🔐 Armazene a credencial em variável de ambiente ou gerenciador de secrets",
            "4. 🗑️  Remova a credencial do código-fonte",
            "5. 🧹 Use ferramentas como git-filter-branch ou BFG Repo-Cleaner para remover do histórico do Git",
            "6. 👀 Monitore logs do serviço para uso não autorizado",
        ]

        env_examples = {
            'python': "import os\napi_key = os.getenv('API_KEY')",
            'javascript': "const apiKey = process.env.API_KEY;",
            'java': "String apiKey = System.getenv(\"API_KEY\");",
            'csharp': "string apiKey = Environment.GetEnvironmentVariable(\"API_KEY\");",
            'go': "apiKey := os.Getenv(\"API_KEY\")",
            'ruby': "api_key = ENV['API_KEY']",
            'php': "$api_key = getenv('API_KEY');",
        }

        # Adicionar exemplos específicos
        if 'aws' in secret_type.lower():
            common_steps.append(
                "7. 📚 Considere usar AWS Secrets Manager ou AWS Systems Manager Parameter Store"
            )
        elif 'github' in secret_type.lower():
            common_steps.append(
                "7. 📚 Use GitHub Secrets para Actions ou variáveis de ambiente"
            )
        elif 'stripe' in secret_type.lower():
            common_steps.append(
                "7. 📚 Use Stripe Environment Variables e nunca comite live keys"
            )

        common_steps.append("\n📖 Exemplo de uso correto com variáveis de ambiente:")
        common_steps.append(f"```python\n{env_examples.get('python', '')}\n```")

        return common_steps

    def get_statistics(self, findings: List[Finding]) -> Dict[str, any]:
        """
        Calcula estatísticas sobre secrets detectados.

        Args:
            findings: Lista de findings de secrets

        Returns:
            Dicionário com estatísticas
        """
        stats = {
            'total_secrets': len(findings),
            'by_type': {},
            'by_severity': {},
            'files_affected': len(set(f.file for f in findings))
        }

        for finding in findings:
            # Por tipo
            secret_type = finding.context.get('secret_type', 'unknown')
            stats['by_type'][secret_type] = stats['by_type'].get(secret_type, 0) + 1

            # Por severity
            severity = finding.severity.name
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

        return stats
