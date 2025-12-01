"""
BetaCode - SAST Analyzer

Este módulo realiza análise estática de código (SAST) para detectar
vulnerabilidades de segurança usando regras baseadas em padrões.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

from typing import List, Dict, Optional
from ..core.base_types import Finding, Severity, FindingType
from ..core.rule_engine import RuleEngine
from ..core.exceptions import AnalysisError
from .pattern_matcher import PatternMatcher
from ..utils.logger import get_logger

logger = get_logger(__name__)


class SASTAnalyzer:
    """
    Analisador estático de código para detectar vulnerabilidades de segurança.

    Detecta:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Command Injection
    - Path Traversal
    - Insecure Deserialization
    - XML External Entity (XXE)
    - Server-Side Request Forgery (SSRF)
    - Cross-Site Request Forgery (CSRF)
    - Weak Cryptography
    - Insecure HTTP
    - Missing Authentication
    - Broken Access Control
    - Insecure Random
    - Race Conditions
    """

    def __init__(self, rule_engine: RuleEngine):
        """
        Inicializa o analisador SAST.

        Args:
            rule_engine: Motor de regras configurado
        """
        self.rule_engine = rule_engine
        self.pattern_matcher = PatternMatcher()

    def analyze(
        self,
        code: str,
        language: str,
        file_path: str
    ) -> List[Finding]:
        """
        Analisa código para detectar vulnerabilidades de segurança.

        Args:
            code: Código-fonte para analisar
            language: Linguagem de programação
            file_path: Caminho do arquivo

        Returns:
            Lista de findings de vulnerabilidades

        Raises:
            AnalysisError: Se ocorrer erro durante análise
        """
        try:
            logger.debug(f"Iniciando análise SAST: {file_path} (language: {language})")

            findings = []

            # Obter regras para a linguagem
            rules = self.rule_engine.get_rules_for_language(language)

            if not rules:
                logger.warning(
                    f"Nenhuma regra encontrada para linguagem: {language}"
                )
                return findings

            logger.debug(f"Aplicando {len(rules)} regras para {language}")

            # Aplicar cada regra
            for rule in rules:
                if not rule.enabled:
                    continue

                try:
                    rule_findings = self._apply_rule(rule, code, file_path)
                    findings.extend(rule_findings)

                    if rule_findings:
                        logger.debug(
                            f"Regra {rule.id}: {len(rule_findings)} finding(s)"
                        )

                except Exception as e:
                    logger.error(
                        f"Erro ao aplicar regra {rule.id} em {file_path}: {e}"
                    )
                    continue

            logger.info(
                f"Análise SAST concluída: {len(findings)} finding(s) em {file_path}"
            )

            return findings

        except Exception as e:
            raise AnalysisError(
                f"Erro durante análise SAST de {file_path}",
                details=str(e)
            )

    def _apply_rule(
        self,
        rule,
        code: str,
        file_path: str
    ) -> List[Finding]:
        """
        Aplica uma regra específica ao código.

        Args:
            rule: Regra para aplicar
            code: Código-fonte
            file_path: Caminho do arquivo

        Returns:
            Lista de findings para esta regra
        """
        findings = []

        # Encontrar matches do pattern
        matches = self.pattern_matcher.find_matches(
            pattern=rule.pattern,
            code=code,
            rule_id=rule.id,
            case_sensitive=True,
            multiline=True
        )

        # Criar finding para cada match
        for line_num, col_num, matched_text in matches:
            # Extrair snippet de código (linha com contexto)
            code_lines = code.split('\n')
            snippet = self._extract_snippet(code_lines, line_num)

            # Determinar CVSS se aplicável
            cvss, cvss_vector = self._calculate_cvss(rule)

            # Criar finding
            finding = Finding(
                id=Finding.generate_id(file_path, line_num, rule.id),
                rule_id=rule.id,
                finding_type=FindingType.VULNERABILITY,
                severity=Severity[rule.severity.upper()],
                file=file_path,
                line=line_num,
                column=col_num,
                message=self._format_message(rule, matched_text),
                code_snippet=snippet,
                cwe=rule.cwe,
                cvss=cvss,
                cvss_vector=cvss_vector,
                owasp=rule.owasp,
                remediations=self._get_remediations(rule),
                references=rule.references,
                context={
                    'matched_text': matched_text,
                    'rule_name': rule.name,
                    'rule_category': rule.category,
                    'rule_tags': rule.tags
                }
            )

            findings.append(finding)

        return findings

    def _extract_snippet(
        self,
        code_lines: List[str],
        line_num: int,
        context_lines: int = 2
    ) -> str:
        """
        Extrai snippet de código com contexto.

        Args:
            code_lines: Linhas do código
            line_num: Número da linha (1-indexed)
            context_lines: Número de linhas de contexto antes/depois

        Returns:
            Snippet formatado
        """
        start = max(0, line_num - context_lines - 1)
        end = min(len(code_lines), line_num + context_lines)

        lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            lines.append(f"{prefix}{code_lines[i]}")

        return '\n'.join(lines)

    def _format_message(self, rule, matched_text: str) -> str:
        """
        Formata mensagem do finding.

        Args:
            rule: Regra aplicada
            matched_text: Texto que deu match

        Returns:
            Mensagem formatada
        """
        if rule.message_template:
            # Substituir placeholders no template
            message = rule.message_template.replace('{match}', matched_text)
            return message

        return f"{rule.name}: {rule.description}"

    def _get_remediations(self, rule) -> List[str]:
        """
        Retorna passos de remediação para uma regra.

        Args:
            rule: Regra

        Returns:
            Lista de passos de remediação
        """
        remediations = []

        if rule.remediation:
            remediations.append(rule.remediation)

        # Adicionar remediações genéricas baseadas no CWE
        if rule.cwe:
            generic_remediations = self._get_generic_remediations(rule.cwe)
            remediations.extend(generic_remediations)

        return remediations if remediations else ["Revise o código e consulte as referências"]

    def _get_generic_remediations(self, cwe: str) -> List[str]:
        """
        Retorna remediações genéricas baseadas no CWE.

        Args:
            cwe: CWE ID (ex: CWE-89)

        Returns:
            Lista de remediações
        """
        remediation_map = {
            'CWE-89': [  # SQL Injection
                "Use prepared statements ou queries parametrizadas",
                "Nunca concatene input do usuário diretamente em queries SQL",
                "Use ORMs com validação automática",
                "Valide e sanitize todo input do usuário"
            ],
            'CWE-79': [  # XSS
                "Escape todo output enviado ao browser",
                "Use Content Security Policy (CSP)",
                "Valide e sanitize input do usuário",
                "Use frameworks com auto-escaping (React, Vue, Angular)"
            ],
            'CWE-78': [  # Command Injection
                "Nunca execute comandos com input não validado",
                "Use bibliotecas específicas ao invés de shell commands",
                "Valide input contra whitelist de valores permitidos",
                "Use funções que não invocam shell (exec vs system)"
            ],
            'CWE-22': [  # Path Traversal
                "Valide caminhos de arquivo contra path traversal",
                "Use funções de normalização de caminho",
                "Restrinja acesso a diretórios específicos",
                "Nunca concatene input do usuário diretamente em paths"
            ],
            'CWE-502': [  # Insecure Deserialization
                "Nunca deserialize dados não confiáveis",
                "Use formatos de dados seguros (JSON ao invés de pickle/marshal)",
                "Implemente validação de tipo após deserialização",
                "Use assinaturas digitais para verificar integridade"
            ],
            'CWE-611': [  # XXE
                "Desabilite entidades externas em parsers XML",
                "Use bibliotecas XML seguras",
                "Valide schemas XML",
                "Prefira JSON ao invés de XML quando possível"
            ],
            'CWE-327': [  # Weak Cryptography
                "Use algoritmos criptográficos fortes (AES-256, SHA-256+)",
                "Nunca use MD5 ou SHA-1 para segurança",
                "Use bibliotecas criptográficas estabelecidas",
                "Implemente key rotation"
            ],
            'CWE-259': [  # Hardcoded Password
                "Use variáveis de ambiente para credenciais",
                "Use gerenciadores de secrets (Vault, AWS Secrets Manager)",
                "Nunca comite credenciais no código",
                "Implemente rotação automática de credenciais"
            ],
            'CWE-319': [  # Cleartext Transmission
                "Use HTTPS/TLS para toda comunicação",
                "Implemente HSTS (HTTP Strict Transport Security)",
                "Desabilite protocolos inseguros (HTTP, FTP, Telnet)",
                "Use certificados válidos e atualizados"
            ],
            'CWE-306': [  # Missing Authentication
                "Implemente autenticação em todos os endpoints sensíveis",
                "Use OAuth 2.0 ou similar",
                "Implemente rate limiting",
                "Use autenticação multifator quando apropriado"
            ],
            'CWE-352': [  # CSRF
                "Use tokens CSRF",
                "Valide origem das requisições",
                "Use SameSite cookies",
                "Implemente verificação de referer"
            ],
            'CWE-918': [  # SSRF
                "Valide e sanitize URLs fornecidas por usuários",
                "Use whitelist de domínios/IPs permitidos",
                "Bloqueie acesso a redes privadas (localhost, 127.0.0.1, 10.x, 192.168.x)",
                "Use network segmentation"
            ],
        }

        cwe_normalized = cwe.upper().replace('CWE-', 'CWE-')
        return remediation_map.get(cwe_normalized, [])

    def _calculate_cvss(self, rule) -> tuple[Optional[float], Optional[str]]:
        """
        Calcula CVSS score baseado na severity e tipo de vulnerabilidade.

        Args:
            rule: Regra

        Returns:
            Tupla (cvss_score, cvss_vector)
        """
        # Mapeamento simplificado severity -> CVSS
        severity_to_cvss = {
            'CRITICAL': (9.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'),
            'HIGH': (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'),
            'MEDIUM': (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'),
            'LOW': (3.7, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N'),
            'INFO': (0.0, None),
        }

        return severity_to_cvss.get(rule.severity, (None, None))

    def get_statistics(self, findings: List[Finding]) -> Dict[str, any]:
        """
        Calcula estatísticas sobre vulnerabilidades encontradas.

        Args:
            findings: Lista de findings

        Returns:
            Dicionário com estatísticas
        """
        stats = {
            'total_vulnerabilities': len(findings),
            'by_severity': {},
            'by_cwe': {},
            'by_owasp': {},
            'by_category': {},
            'critical_count': 0,
            'high_count': 0,
            'files_affected': len(set(f.file for f in findings))
        }

        for finding in findings:
            # Por severity
            severity = finding.severity.name
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

            if severity == 'CRITICAL':
                stats['critical_count'] += 1
            elif severity == 'HIGH':
                stats['high_count'] += 1

            # Por CWE
            if finding.cwe:
                stats['by_cwe'][finding.cwe] = stats['by_cwe'].get(finding.cwe, 0) + 1

            # Por OWASP
            if finding.owasp:
                stats['by_owasp'][finding.owasp] = stats['by_owasp'].get(finding.owasp, 0) + 1

            # Por categoria
            category = finding.context.get('rule_category', 'other')
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1

        return stats
