"""
BetaCode - Tipos de Dados Base

Este módulo define todos os tipos de dados fundamentais utilizados
no BetaCode para representar resultados de análise, vulnerabilidades,
regras e configurações.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime
import uuid


class Severity(Enum):
    """
    Níveis de severidade para vulnerabilidades.

    CRITICAL: Vulnerabilidades críticas que requerem ação imediata
    HIGH: Vulnerabilidades de alta severidade
    MEDIUM: Vulnerabilidades de média severidade
    LOW: Vulnerabilidades de baixa severidade
    INFO: Informações e avisos
    """
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    def __str__(self) -> str:
        return self.name

    def to_color(self) -> str:
        """Retorna cor para exibição em terminal"""
        colors = {
            'CRITICAL': '\033[91m',  # Vermelho
            'HIGH': '\033[93m',       # Amarelo
            'MEDIUM': '\033[94m',     # Azul
            'LOW': '\033[92m',        # Verde
            'INFO': '\033[96m'        # Ciano
        }
        return colors.get(self.name, '')


class FindingType(Enum):
    """
    Tipos de findings que podem ser detectados.

    VULNERABILITY: Vulnerabilidades de segurança
    SECRET: Credenciais e secrets expostos
    QUALITY: Problemas de qualidade de código
    COMPLIANCE: Violações de compliance/standards
    DEPENDENCY: Problemas com dependências
    PERFORMANCE: Problemas de performance
    """
    VULNERABILITY = "vulnerability"
    SECRET = "secret"
    QUALITY = "quality"
    COMPLIANCE = "compliance"
    DEPENDENCY = "dependency"
    PERFORMANCE = "performance"

    def __str__(self) -> str:
        return self.value


class FindingStatus(Enum):
    """Status de um finding"""
    OPEN = "open"
    FIXED = "fixed"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"
    IN_PROGRESS = "in_progress"

    def __str__(self) -> str:
        return self.value


@dataclass
class Finding:
    """
    Representa um resultado individual de análise (vulnerabilidade, issue, etc).

    Attributes:
        id: Identificador único do finding
        rule_id: ID da regra que detectou o finding
        finding_type: Tipo do finding (vulnerability, secret, etc)
        severity: Nível de severidade
        file: Caminho do arquivo onde foi encontrado
        line: Número da linha
        column: Número da coluna
        message: Descrição do problema
        code_snippet: Trecho do código afetado
        cwe: CWE ID (ex: CWE-79 para XSS)
        cvss: CVSS score (0.0 a 10.0)
        cvss_vector: CVSS vector string
        owasp: Categoria OWASP (ex: A03:2021 - Injection)
        remediations: Lista de passos para remediar
        references: Links para documentação
        status: Status atual do finding
        first_seen: Data/hora da primeira detecção
        last_seen: Data/hora da última detecção
        context: Informações contextuais adicionais
    """
    id: str
    rule_id: str
    finding_type: FindingType
    severity: Severity
    file: str
    line: int
    column: int
    message: str
    code_snippet: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    cvss_vector: Optional[str] = None
    owasp: Optional[str] = None
    remediations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    context: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def generate_id(file: str, line: int, rule_id: str) -> str:
        """Gera ID único para um finding"""
        base = f"{file}:{line}:{rule_id}"
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, base))

    def to_dict(self) -> Dict[str, Any]:
        """Converte finding para dicionário"""
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'finding_type': self.finding_type.value,
            'severity': self.severity.name,
            'file': self.file,
            'line': self.line,
            'column': self.column,
            'message': self.message,
            'code_snippet': self.code_snippet,
            'cwe': self.cwe,
            'cvss': self.cvss,
            'cvss_vector': self.cvss_vector,
            'owasp': self.owasp,
            'remediations': self.remediations,
            'references': self.references,
            'status': self.status.value,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'context': self.context
        }

    def __str__(self) -> str:
        return f"[{self.severity.name}] {self.rule_id} - {self.file}:{self.line}"


@dataclass
class AnalysisResult:
    """
    Resultado completo de uma análise de código.

    Attributes:
        timestamp: Data/hora da análise
        target: Arquivo ou diretório analisado
        total_findings: Número total de findings
        findings: Lista de todos os findings
        metrics: Métricas da análise
        duration_seconds: Duração da análise em segundos
        files_scanned: Número de arquivos escaneados
        files_failed: Número de arquivos com falha
        errors: Lista de erros encontrados
        version: Versão do BetaCode
        config: Configuração utilizada
    """
    timestamp: str
    target: str
    total_findings: int
    findings: List[Finding]
    metrics: Dict[str, Any]
    duration_seconds: float
    files_scanned: int
    files_failed: int = 0
    errors: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    config: Optional[Dict[str, Any]] = None

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Retorna findings filtrados por severidade"""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_type(self, finding_type: FindingType) -> List[Finding]:
        """Retorna findings filtrados por tipo"""
        return [f for f in self.findings if f.finding_type == finding_type]

    def get_critical_findings(self) -> List[Finding]:
        """Retorna apenas findings críticos"""
        return self.get_findings_by_severity(Severity.CRITICAL)

    def get_high_findings(self) -> List[Finding]:
        """Retorna apenas findings de alta severidade"""
        return self.get_findings_by_severity(Severity.HIGH)

    def has_critical_findings(self) -> bool:
        """Verifica se há findings críticos"""
        return len(self.get_critical_findings()) > 0

    def to_dict(self) -> Dict[str, Any]:
        """Converte resultado para dicionário"""
        return {
            'timestamp': self.timestamp,
            'target': self.target,
            'total_findings': self.total_findings,
            'findings': [f.to_dict() for f in self.findings],
            'metrics': self.metrics,
            'duration_seconds': self.duration_seconds,
            'files_scanned': self.files_scanned,
            'files_failed': self.files_failed,
            'errors': self.errors,
            'version': self.version,
            'config': self.config
        }


@dataclass
class Rule:
    """
    Definição de uma regra de análise.

    Attributes:
        id: Identificador único da regra
        name: Nome da regra
        description: Descrição detalhada
        pattern: Padrão regex ou pattern para matching
        severity: Nível de severidade
        language: Linguagem alvo (python, javascript, etc)
        cwe: CWE ID relacionado
        owasp: Categoria OWASP relacionada
        message_template: Template de mensagem para findings
        remediation: Descrição de como remediar
        references: Links para documentação
        enabled: Se a regra está habilitada
        tags: Tags para categorização
        category: Categoria da regra (injection, crypto, etc)
    """
    id: str
    name: str
    description: str
    pattern: str
    severity: str
    language: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    message_template: str = ""
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    category: str = "security"

    def to_dict(self) -> Dict[str, Any]:
        """Converte regra para dicionário"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'pattern': self.pattern,
            'severity': self.severity,
            'language': self.language,
            'cwe': self.cwe,
            'owasp': self.owasp,
            'message_template': self.message_template,
            'remediation': self.remediation,
            'references': self.references,
            'enabled': self.enabled,
            'tags': self.tags,
            'category': self.category
        }


@dataclass
class Dependency:
    """
    Representa uma dependência de projeto.

    Attributes:
        name: Nome do pacote/biblioteca
        version: Versão instalada
        language: Linguagem (python, javascript, java, etc)
        manager: Gerenciador de pacotes (pip, npm, maven, etc)
        type: Tipo (direct, transitive)
        path: Caminho do arquivo de dependências
        vulnerabilities: Lista de CVE IDs
        latest_version: Última versão disponível
        is_outdated: Se está desatualizado
        license: Licença do pacote
    """
    name: str
    version: str
    language: str
    manager: str
    type: str
    path: str
    vulnerabilities: List[str] = field(default_factory=list)
    latest_version: Optional[str] = None
    is_outdated: bool = False
    license: Optional[str] = None

    def has_vulnerabilities(self) -> bool:
        """Verifica se tem vulnerabilidades"""
        return len(self.vulnerabilities) > 0

    def to_dict(self) -> Dict[str, Any]:
        """Converte dependência para dicionário"""
        return {
            'name': self.name,
            'version': self.version,
            'language': self.language,
            'manager': self.manager,
            'type': self.type,
            'path': self.path,
            'vulnerabilities': self.vulnerabilities,
            'latest_version': self.latest_version,
            'is_outdated': self.is_outdated,
            'license': self.license
        }


@dataclass
class Config:
    """
    Configuração da análise.

    Attributes:
        languages: Linguagens a analisar
        timeout: Timeout em segundos
        workers: Número de workers paralelos
        max_file_size: Tamanho máximo de arquivo em MB
        exclude_patterns: Padrões de arquivos a excluir
        severity_level: Nível mínimo de severidade
        fail_on_critical: Se deve falhar ao encontrar críticos
        output_formats: Formatos de output (json, html, sarif, pdf)
        output_directory: Diretório de output
        integrations: Configurações de integrações
        rules_path: Caminho para regras customizadas
        enable_secret_detection: Habilitar detecção de secrets
        enable_dependency_analysis: Habilitar análise de dependências
        enable_quality_analysis: Habilitar análise de qualidade
    """
    languages: List[str] = field(default_factory=list)
    timeout: int = 300
    workers: int = 4
    max_file_size: int = 10  # MB
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "*.min.js", "*.min.css", "node_modules/**", "__pycache__/**",
        ".git/**", ".venv/**", "venv/**", "*.pyc", "dist/**", "build/**"
    ])
    severity_level: str = "LOW"
    fail_on_critical: bool = True
    output_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    output_directory: str = "./betacode-reports"
    integrations: Dict[str, Any] = field(default_factory=dict)
    rules_path: Optional[str] = None
    enable_secret_detection: bool = True
    enable_dependency_analysis: bool = True
    enable_quality_analysis: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Converte configuração para dicionário"""
        return {
            'languages': self.languages,
            'timeout': self.timeout,
            'workers': self.workers,
            'max_file_size': self.max_file_size,
            'exclude_patterns': self.exclude_patterns,
            'severity_level': self.severity_level,
            'fail_on_critical': self.fail_on_critical,
            'output_formats': self.output_formats,
            'output_directory': self.output_directory,
            'integrations': self.integrations,
            'rules_path': self.rules_path,
            'enable_secret_detection': self.enable_secret_detection,
            'enable_dependency_analysis': self.enable_dependency_analysis,
            'enable_quality_analysis': self.enable_quality_analysis
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Config':
        """Cria Config a partir de dicionário"""
        return Config(**data)


# Type aliases para facilitar uso
FindingsList = List[Finding]
RulesList = List[Rule]
DependenciesList = List[Dependency]
